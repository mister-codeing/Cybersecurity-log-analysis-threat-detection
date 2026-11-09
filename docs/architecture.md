# Architecture

The tool is a **pipeline**: every stage takes the output of the previous one and
has exactly one job. This keeps each file small and easy to test on its own.

```
             ┌──────────────┐   normalized    ┌──────────────┐  alerts
 .evtx ────► │  parser.py   │ ───events────►  │  engine.py   │ ───────────┐
 files       │ EVTX→XML→dict│        │        │ single-event │            │
             └──────────────┘        │        │    rules     │            ▼
                                     │        └──────▲───────┘     ┌──────────────┐
                                     │               │ rules/*.yml │  report.py   │──► console
                                     │        ┌──────┴───────┐     │              │──► alerts.csv
                                     └──────► │correlation.py│ ──► │              │──► alerts.json
                          (only events a      │ threshold &  │     │              │──► report.html
                           correlation rule   │  sequence    │     └──────────────┘
                           needs are kept)    └──────▲───────┘
                                                     │ config.yml / --threshold / --timeframe
```

`main.py` connects the stages, reads command-line options and handles errors.

## 1. Parsing - `detector/parser.py`

An EVTX file is a binary format. The `python-evtx` library reads each record
and gives us its XML; `xmltodict` turns the XML into nested Python dicts.
`normalize()` then flattens it into one simple shape:

```python
{
  "event_id": 4625,
  "time": "2024-01-01T10:00:00.123456+00:00",   # always ISO 8601, UTC
  "channel": "Security",
  "computer": "DC01.lab.local",
  "provider": "Microsoft-Windows-Security-Auditing",
  "record_id": 42,
  "data": {"TargetUserName": "bob", "IpAddress": "10.0.0.5", ...}
}
```

Edge cases handled (each one has a unit test):

| Situation | Handling |
|---|---|
| `<EventID Qualifiers="16384">7045</EventID>` | read the text value |
| Fields in `<UserData>` instead of `<EventData>` (1102, 104, 1149, 21...) | flattened into `data` |
| Only one `<Data>` element (xmltodict returns a dict, not a list) | wrapped into a list |
| `<Data>` without a `Name` attribute | stored as `param1`, `param2`, ... |
| Empty `<Data Name="X"/>` | value `None` |
| Timestamps with 7 decimals and `Z`, or with a space instead of `T` | normalized to ISO UTC |
| Corrupt record | skipped, rest of the file continues |
| Corrupt / empty / non-EVTX file | exception caught in `main.py`, warning printed, other files continue |

`parse_evtx()` is a **generator** (`yield`): events are produced one at a time,
so a large file is never fully loaded into memory.

## 2. Rules engine - `detector/engine.py`

- `load_rules()` reads every YAML file in `rules/` (several rules per file
  are allowed with `---`) and **validates** them (required keys, known
  severity, known operators, unique ids, valid correlation type).
- `matches(selection, event)` checks one event against a `detection` block:
  1. `event_id` must be in the list
  2. `channel` must match (case-insensitive)
  3. every condition in `fields` must be true (**AND** between fields,
     **OR** between the values of one field)
  4. no condition in `exclude` may be true
- `detect_event()` applies all single-event rules to one event and builds
  alerts with `make_alert()`. Rules that have a `correlation:` section are
  skipped here.

Why YAML rules? The program contains no attack-specific logic. An analyst can
add, disable or tune detections by editing text files - the same idea used by
Sigma, Chainsaw and Hayabusa.

## 3. Correlation - `detector/correlation.py`

Some attacks are only visible as a **pattern** of events. Correlation rules
reuse the same `detection` syntax to select events, then:

1. **Group** the selected events by the `group_by` fields
   (e.g. all failed logons from IP `10.0.0.9`).
2. **Sort** each group by time.
3. Apply the rule type:

**Threshold** - a *sliding window*: for each event (window end) the window start
moves forward until the window is not longer than `timeframe`. If the window
contains at least `threshold` events (or `threshold` *different* values of the
`distinct` field), an alert is raised. Following events that continue the same
burst are absorbed into that alert, so a 1-hour attack produces **one** alert
with the full count instead of hundreds.

```
time ─►  x   x x x  x               x        x
         └── 10 min window ──┘
         5 events in window  → ALERT
```

**Sequence** - walk through the group in time order, remembering recent step-1
events (failures) in a queue. When a step-2 event (success) arrives, failures
older than `timeframe` are removed from the queue; if at least `threshold`
remain, the attack succeeded → critical alert.

Settings are merged with this priority: rule YAML < `config.yml` < CLI options.

To save memory, `main.py` keeps only events that some correlation rule needs
(`is_relevant()`), and correlation runs once over **all** files together - this
is what allows "same account on many hosts" when logs from several machines
are analysed together.

## 4. Reporting - `detector/report.py`

All formats use the same alert dict:

```python
{"time", "computer", "rule", "rule_id", "level", "mitre", "description", "details"}
```

| Format | Use |
|---|---|
| console | quick overview: totals per severity and technique, then alerts in time order |
| CSV | open in Excel / import into other tools (`utf-8-sig` so Excel shows characters correctly) |
| JSON | machine-readable: scan info, summary and all alerts |
| HTML | one self-contained file: summary cards, technique table with links to attack.mitre.org, sortable alerts table (small inline JavaScript), color-coded timeline. All event data is HTML-escaped so a malicious log cannot inject script into the report. |

## 5. Command line - `main.py`

1. Parse options with `argparse` and validate them (formats, timeframe, threshold).
2. Load rules and `config.yml`.
3. Expand folders into `.evtx` files (recursive).
4. For each file: parse, run single-event rules, keep events for correlation.
   Errors in one file are reported and the next file is processed.
5. Run correlation over all kept events.
6. Filter by `--min-level`, write the requested reports.
7. Exit code `0` (ok) or `2` (error).
