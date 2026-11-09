# Cybersecurity Log Analysis & Threat Detection System

A lightweight Python command-line tool that reads **Windows Event Logs (EVTX)**,
detects attacker activity with **external YAML rules**, correlates related
events over time, and maps every alert to **MITRE ATT&CK**.
It is inspired by [Chainsaw](https://github.com/WithSecureLabs/chainsaw) and
[Hayabusa](https://github.com/Yamato-Security/hayabusa), but is intentionally
small so every part can be read and explained.

> Graduation project - scope: Windows EVTX files only, four attack techniques.

---

## Features

- Parses `.evtx` files (single files or whole folders, recursively) into a simple, normalized event format
- Detection logic lives in **YAML rules**, not in Python code - add or tune a rule without touching the program
- Field filters with `equals`, `contains`, `startswith`, `endswith` (case-insensitive) and `exclude` filters
- **Correlation engine**: threshold rules ("N events in T minutes") and sequence rules ("N failures *then* a success")
- Thresholds configurable per rule in `config.yml` or globally with `--threshold` / `--timeframe`
- Reports: **console** summary, **CSV**, **JSON** and a single-file **HTML** report (sortable table, severity colors, MITRE links, timeline)
- Graceful error handling: corrupt files, empty files, missing paths, invalid rules
- 94 automated `pytest` tests that run without any real EVTX file
- Optional **web dashboard** (Streamlit) with charts, filters and exports - see [Dashboard](#dashboard-optional)

## Supported detections

| Technique | MITRE ID | Event IDs (log) | Rule file | Severity |
|---|---|---|---|---|
| Brute Force - many failed logons | [T1110](https://attack.mitre.org/techniques/T1110/) | 4625 (Security) | `brute_force.yml` | medium |
| Brute Force **succeeded** (failures -> success) | T1110 | 4625 then 4624 (Security) | `brute_force.yml` | **critical** |
| Kerberos brute force / password spray | T1110 | 4771 (Security, DC) | `brute_force.yml` | medium |
| NTLM brute force | T1110 | 4776 (Security) | `brute_force.yml` | medium |
| Security log cleared | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | 1102 (Security) | `log_clearing.yml` | high |
| Other Windows log cleared | T1070.001 | 104 (System) | `log_clearing.yml` | high |
| Suspicious service installed | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | 7045 (System), 4697 (Security) | `persistence_service.yml` | high |
| Suspicious scheduled task created | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | 4698 (Security) | `persistence_task.yml` | high |
| Scheduled task registered (info) | T1053.005 | 106 (TaskScheduler/Operational) | `persistence_task.yml` | low |
| RDP logon from remote address | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | 4624 LogonType 10/12 (Security) | `rdp_lateral.yml` | low |
| RDP authentication / session events | T1021.001 | 1149, 261 (RemoteConnectionManager), 21, 22, 25 (LocalSessionManager) | `rdp_lateral.yml` | low |
| RDP - same account on many hosts | T1021.001 | 4624 LogonType 10/12 (correlated) | `rdp_lateral.yml` | high |
| RDP - same account from many sources | T1021.001 | 4624 LogonType 10/12 (correlated) | `rdp_lateral.yml` | medium |

"Suspicious" for services and tasks means the command contains one of:
`\temp\`, `\appdata\`, `\users\public\`, `\programdata\`, `powershell`, `cmd.exe`,
`%comspec%`, `mshta`, `rundll32`, `regsvr32`, ` -enc` / ` -ec ` (encoded PowerShell),
`frombase64string`. More detail: [docs/detections.md](docs/detections.md).

## Architecture

```
 .evtx files ──► parser.py ──► normalized events ──► engine.py ──────────► alerts ──► report.py
                (EVTX→XML→dict)                     (single-event rules)    ▲         console / CSV
                                                          │                 │         JSON / HTML
                                    rules/*.yml ──────────┤                 │
                                    config.yml ──► correlation.py ──────────┘
                                                  (threshold & sequence rules)
```

| File | Responsibility |
|---|---|
| `detector/parser.py` | Opens an EVTX file, converts each record's XML into a normalized dict (`event_id`, `time` in ISO UTC, `channel`, `computer`, `provider`, `record_id`, `data`). Handles both `EventData` and `UserData`. |
| `detector/engine.py` | Loads and validates YAML rules, matches a single event against a rule, builds alert dicts. |
| `detector/correlation.py` | Rules that need several events: groups events, applies sliding time windows (threshold) and "step 1 then step 2" logic (sequence). |
| `detector/report.py` | Console summary, CSV, JSON and HTML reports. |
| `detector/pipeline.py` | Runs the whole pipeline (`run_pipeline()`); shared by the CLI and the dashboard so detection code exists only once. |
| `detector/dashboard_data.py` | Pure-Python data preparation for the dashboard (filters, counts, timeline, upload checks). |
| `main.py` | Command-line interface: options, error messages, report files. |
| `dashboard.py` | Optional Streamlit web dashboard (user interface only). |
| `rules/` | One YAML file per technique. |
| `config.yml` | Optional threshold/time-window overrides per correlation rule. |

Full explanation: [docs/architecture.md](docs/architecture.md).

## Installation

Requires Python 3.10 or newer.

```bash
git clone https://github.com/mister-codeing/Cybersecurity-log-analysis-threat-detection.git
cd Cybersecurity-log-analysis-threat-detection
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt          # runtime
pip install -r requirements-dev.txt      # + pytest, for running the tests
```

## Usage

```bash
# Analyse one file, print results to the console
python main.py samples/DE_1102_security_log_cleared.evtx

# Analyse every .evtx in a folder and create all reports in ./output
python main.py samples/ --format console,csv,json,html --output output

# Stricter brute-force detection, only show medium and above
python main.py logs/ --threshold 10 --timeframe 5m --min-level medium

# Use a different rules folder / config file
python main.py logs/ --rules my_rules --config my_config.yml
```

| Option | Default | Meaning |
|---|---|---|
| `paths` | - | One or more `.evtx` files and/or folders |
| `-r, --rules` | `rules` | Folder containing YAML rules |
| `-o, --output` | `output` | Folder for CSV/JSON/HTML reports |
| `-f, --format` | `console` | Comma-separated: `console`, `csv`, `json`, `html` |
| `-c, --config` | `config.yml` | Correlation settings (optional file) |
| `--threshold` | from rules | Override the threshold of **all** correlation rules |
| `--timeframe` | from rules | Override the window of **all** correlation rules (`30s`, `10m`, `1h`) |
| `--min-level` | `low` | Hide alerts below this severity |

Report files: `output/alerts.csv`, `output/alerts.json`, `output/report.html`.
Exit code: `0` = success, `2` = error (bad option, invalid rules, no readable file).

Example console output:

```
[*] Loaded 16 rule(s), analysing 1 file(s)...
======================================================================
 DETECTION SUMMARY
======================================================================
 Files analysed : 1
 Events parsed  : 112
 Rules loaded   : 16
 Alerts         : 1  (high 1)

 Alerts per MITRE ATT&CK technique:
   T1070.001  Indicator Removal: Clear Windows Event Logs           1

======================================================================
 ALERTS (chronological)
======================================================================
[HIGH] 2019-03-19T23:35:07.524200+00:00 | PC01.example.corp | Security Log Cleared (T1070.001)
        SubjectUserName: user01
        SubjectDomainName: EXAMPLE
[*] Total alerts: 1
```

## Dashboard (optional)

A small web dashboard built with [Streamlit](https://streamlit.io) shows the same
results visually. It is **optional**: the command-line tool works without
installing anything from this section.

```bash
pip install -r requirements-dashboard.txt     # streamlit, pandas, altair
streamlit run dashboard.py                    # opens http://localhost:8501
```

What it shows:

- **Sidebar** - upload one or more `.evtx` files, *or* enter a folder path (e.g. `samples`);
  number inputs for the correlation thresholds (brute-force failures + window,
  RDP hosts/sources + window), pre-filled from `config.yml`
- **Metric cards** - events parsed, total alerts, Critical / High / Medium / Low
- **Charts** - alerts by severity, by MITRE ATT&CK technique, and over time (stacked by severity)
- **Alerts table** - sortable (click a header), filterable by severity, technique, rule and
  computer, plus a free-text search (user names, IPs, commands...)
- **Alert details** - select a row to see every field and a link to the technique on attack.mitre.org
- **Export** - filtered alerts as CSV / JSON, and the full HTML report (same generator as the CLI)

Charts, table and CSV/JSON exports follow the filters; the metric cards and the HTML
report always cover all alerts.

How it is built:

- It calls `detector.pipeline.run_pipeline()` - no detection logic in the dashboard.
- Results are cached with `st.cache_data`: changing a filter does not re-parse the files;
  changing files, thresholds or rule files does.
- Security: log content is treated as untrusted and only displayed as plain text
  (no `unsafe_allow_html`). Uploads must have the `.evtx` extension and the EVTX file header,
  are saved under a sanitized name in a temporary folder and deleted after analysis.
  CSV exports neutralize spreadsheet formulas (`=`, `+`, `-`, `@`).
- The folder option reads folders on the computer running Streamlit, so the dashboard is
  meant to be run **locally**, not exposed on a network.

### Screenshots

> _Placeholder - add your own screenshots to `docs/screenshots/` and uncomment the lines below._

<!--
![Dashboard overview](docs/screenshots/dashboard_overview.png)
![Alerts table and details](docs/screenshots/dashboard_alerts.png)
![HTML report](docs/screenshots/html_report.png)
-->

## Rule format

Each rule is a YAML document. Several rules can share a file, separated by `---`.

```yaml
title: Suspicious Service Installed      # shown in the alert
id: rule-003                             # unique id
level: high                              # low | medium | high | critical
mitre: T1543.003                         # MITRE ATT&CK technique id
description: New service with a suspicious binary path
detection:
  event_id: [7045]                       # event must have one of these IDs
  channel: System                        # optional: one value or a list
  fields:                                # optional: ALL conditions must be true
    ImagePath|contains:                  #   FieldName|operator
      - '\temp\'                         #   a list means ANY value may match
      - 'powershell'
  exclude:                               # optional: drop the event if ANY condition is true
    AccountName|equals: 'NT AUTHORITY\LocalService'
show: [ServiceName, ImagePath]           # fields copied into the alert
```

- Operators: `equals` (default if no `|operator`), `contains`, `startswith`, `endswith`. All comparisons ignore case.
- Field names refer to the event's `data` (e.g. `TargetUserName`, `IpAddress`), or to the top-level keys `computer`, `channel`, `provider`, `event_id`.
- Rules are validated on load: a missing key, unknown level or unknown operator stops the program with a clear message.

### Correlation rules

Adding a `correlation:` section turns a rule into a multi-event rule.

```yaml
# Threshold: >= 5 failed logons from the same IP within 10 minutes
correlation:
  type: threshold
  group_by: [IpAddress]       # events with the same value(s) form a group
  threshold: 5
  timeframe: 10m              # s, m or h
  distinct: computer          # optional: count different values instead of events
```

```yaml
# Sequence: >= 5 failed logons, THEN a successful logon from the same IP, within 10 minutes
correlation:
  type: sequence
  group_by: [IpAddress]
  threshold: 5
  timeframe: 10m
  followed_by:                # second step, same syntax as 'detection'
    event_id: [4624]
    exclude:
      LogonType|equals: [0, 5]
```

Settings priority: **rule YAML < `config.yml` < command line**.

```yaml
# config.yml
correlation:
  rule-007:
    threshold: 5
    timeframe: 10m
```

## Sample data

Real attack logs come from the public
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) project
(by Samir Bousseaden). They are **not** stored in this repository (`*.evtx` is in
`.gitignore`). Download the files below into `samples/`:

| File (folder in EVTX-ATTACK-SAMPLES) | Expected result (default settings) |
|---|---|
| `Defense Evasion/DE_1102_security_log_cleared.evtx` | 1 high - Security Log Cleared |
| `Defense Evasion/DE_104_system_log_cleared.evtx` | 1 high - Windows Log Cleared |
| `Lateral Movement/LM_Remote_Service02_7045.evtx` | 2 high - Suspicious Service (`cmd.exe`); the `calc.exe` service is correctly ignored |
| `Privilege Escalation/System_7045_namedpipe_privesc.evtx` | 1 high - Suspicious Service (`%COMSPEC%`) |
| `Execution/temp_scheduled_task_4698_4699.evtx` | 1 high - Suspicious Scheduled Task (`cmd.exe` writing to `%windir%\Temp`) |
| `Privilege Escalation/PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx` | 1 high - Suspicious Scheduled Task (`C:\Users\Public\...`) |
| `Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx` | 2 high - Log Cleared + Suspicious Scheduled Task |
| `Credential Access/kerberos_pwd_spray_4771.evtx` | 1 high (log cleared); with `--threshold 2` also 1 medium - Kerberos Password Spray (only 2 failures in this sample) |
| `Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx` | 36 low - RDP authentication (1149) and listener (261) events |
| `Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx` | 0 - a single failed logon is not brute force (negative test) |

Example download (PowerShell or bash):

```bash
curl -L -o samples/DE_1102_security_log_cleared.evtx "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Defense%20Evasion/DE_1102_security_log_cleared.evtx"
```

The brute-force and multi-host RDP correlations are verified with synthetic events
in `tests/test_correlation.py`, because the public samples do not contain long
password-guessing bursts.

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest            # all tests
python -m pytest -v         # one line per test
```

- `tests/test_parser.py` - XML normalization (EventData, UserData, timestamps, missing fields)
- `tests/test_engine.py` - every operator, AND/OR/exclude logic, rule validation, the real rules
- `tests/test_correlation.py` - thresholds, time windows, grouping, distinct counts, sequences, config priority
- `tests/test_report.py` - summary, CSV, JSON, HTML (including HTML escaping)
- `tests/test_pipeline.py` - the shared `run_pipeline()` function (warnings, corrupt files, progress callback)
- `tests/test_dashboard_data.py` - dashboard helpers: filters, search, counts, timeline buckets, threshold config, upload checks
- `tests/test_cli.py` - CLI options and errors; one **integration test** on the real
  `DE_1102_security_log_cleared.evtx`, automatically **skipped** if the file is missing

## Limitations

- Only Windows EVTX files; no live monitoring, Sysmon or Linux logs.
- Detection depends on audit policy: e.g. 4697/4698 need advanced auditing, 4771 only exists on domain controllers.
- Rules are string-based: an attacker who renames binaries or avoids the listed keywords can evade them; legitimate admin tools may cause false positives (e.g. software installed under `AppData`).
- Correlation keeps relevant events in memory and analyses all given files together; very large log collections need more RAM.
- Correlation thresholds are fixed numbers, not learned baselines of "normal" behaviour.
- The rule language is a simplified subset of Sigma (no regular expressions, no nested AND/OR conditions).
- Timestamps are taken from the logs as they are; clock differences between hosts are not corrected.

## Future work

- Import Sigma rules directly; add regex and numeric comparison operators
- More techniques (Pass-the-Hash, Kerberoasting, PowerShell script-block logging, Sysmon)
- Allow-lists for known admin accounts / hosts to reduce false positives
- Baseline / anomaly detection for "unusual" logon sources
- Streaming correlation for very large datasets; parallel parsing of many files
- Export to SIEM formats (e.g. Elastic Common Schema) and a small web dashboard

## Project structure

```
├── main.py                 CLI entry point
├── dashboard.py            optional Streamlit dashboard
├── config.yml              correlation thresholds
├── detector/
│   ├── parser.py           EVTX -> normalized events
│   ├── engine.py           rule loading, validation, matching
│   ├── correlation.py      threshold & sequence correlation
│   ├── report.py           console / CSV / JSON / HTML
│   ├── pipeline.py         run_pipeline(): used by CLI and dashboard
│   └── dashboard_data.py   data preparation for the dashboard
├── rules/                  YAML rules (one file per technique)
├── tests/                  pytest suite
├── docs/                   architecture and detection documentation
└── samples/                put .evtx files here (not committed)
```
