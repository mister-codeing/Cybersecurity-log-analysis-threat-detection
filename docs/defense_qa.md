# Defence preparation - likely questions and honest answers

Short answers you can say out loud. Numbers come from
[evaluation_results.md](evaluation_results.md) - re-run `python evaluate.py` before the
defence and quote that file, not your memory.

---

**1. What does the system do, in one sentence?**
It reads Windows EVTX log files, checks every event against YAML detection rules,
correlates related events over time (e.g. many failed logons), and reports alerts
mapped to MITRE ATT&CK in the console, CSV, JSON, HTML and an optional dashboard.

**2. What is the architecture?**
A pipeline of small modules, each with one job:
`parser.py` (EVTX → XML → normalized dict) → `engine.py` (single-event rules) →
`correlation.py` (multi-event rules) → `report.py` (output).
`pipeline.py` connects them and is used by both interfaces (`main.py` CLI and
`dashboard.py`), so the detection logic exists only once. See
[architecture.md](architecture.md).

**3. Why YAML rules instead of Python `if` statements?**
Detection knowledge is separated from program code: an analyst can add or tune a rule
without programming, rules are easy to review, and it is the same idea used by Sigma,
Chainsaw and Hayabusa. Rules are validated when loaded (missing keys, unknown
operators or levels stop the program with a clear message).

**4. How does the threshold correlation work?**
Events selected by the rule are grouped (e.g. by `IpAddress`) and sorted by time. A
**sliding window** moves over each group: the window end advances one event at a
time, and the start moves forward until the window is no longer than `timeframe`.
If the window holds at least `threshold` events (or `threshold` *different* values,
with `distinct:`), an alert is raised.

**5. What is "burst merging" and why?**
After the threshold is reached, following events are added to the same alert as long
as each one is within `timeframe` of the previous one. A one-hour attack therefore
gives **one** alert with the full count instead of hundreds - less alert fatigue. A
pause longer than `timeframe` starts a new burst and can produce a new alert.

**6. How do you detect a *successful* brute force?**
A *sequence* rule (rule-008): per source IP, remember recent failures (4625) in a
queue. When a success (4624) arrives, drop failures older than `timeframe`; if at
least `threshold` remain, the password was probably guessed → **critical**. System
and service logons (LogonType 0 and 5) are excluded because they happen constantly.

**7. Why 5 failures in 10 minutes, and 3 hosts in 60 minutes?**
They are reasonable **starting values**, not learned or proven optimal: 5 is close to
common account-lockout policies and users rarely mistype a password 5 times in a row;
one account on 3 different hosts via RDP within an hour is unusual for normal work.
They can be changed per rule in `config.yml`, for all rules with `--threshold` /
`--timeframe`, or in the dashboard. I did not tune them on the evaluation data.

**8. How did you evaluate the tool?**
`evaluate.py` runs the normal pipeline on 11 public EVTX-ATTACK-SAMPLES files and
compares the rules that fired with `tests/expected_results.yml`. The expected rules
were written from each **sample's name and technique**, not copied from the tool's
output - otherwise the test would be circular. Uncertain labels are marked and
explained. It reports PASS/FAIL, missing (FN), unexpected (FP), events and time.

**9. What were the results, and what did it miss?**
Read the current numbers from `evaluation_results.md`. At the time of writing:
9 of 11 real samples passed with default settings, 0 unexpected alerts. Two misses,
both explained:
- `DE_RDP_Tunneling_4624.evtx` - the tunneled RDP logon comes from `127.0.0.1`, and
  rule-011 deliberately ignores loopback to reduce noise. A real design trade-off; a
  separate "RDP logon from loopback" rule is possible future work.
- `kerberos_pwd_spray_4771.evtx` - the file contains only 2 Kerberos failures, below
  the default threshold of 5. With `threshold=2` it is detected, but that run is
  reported separately and **not** counted, because tuning to the test data would be
  cheating.
This is a tiny sample set, so I report raw counts, **not** an accuracy percentage.

**10. Which tests use real data and which are synthetic?**
Real: the 11 EVTX-ATTACK-SAMPLES files in `evaluate.py`, plus two pytest tests on
`DE_1102_security_log_cleared.evtx` (skipped if the file is missing). Synthetic:
almost all unit tests and the SYNTHETIC section of `evaluate.py` (brute force,
password spray, RDP to many hosts / from many IPs, and negative cases). Synthetic
events are needed because the public samples contain no long brute-force bursts and
no multi-host RDP; they show the logic works as designed, not that it works on every
real attack. A real manual test on my own PC is described in [own_logs.md](own_logs.md).

**11. Is the HTML report safe? Log data is controlled by the attacker.**
Yes, for the cases I tested: every value from the logs is passed through
`html.escape()`, so a user name like `<script>` is shown as text (there is a test for
this). The file has no external resources. In CSV exports, cells starting with
`= + - @` are prefixed with `'` to stop formula injection in Excel. The dashboard only
shows log data as plain text (no `unsafe_allow_html`) and checks uploads (extension
+ EVTX header, sanitized file name, temporary folder).

**12. What is the "recommendation" in each alert? Is it AI?**
No. It is a short, fixed text written by me in each YAML rule (e.g. "disable or reset
the account, review the source IP"). It is copied into every alert of that rule. There
is no recommendation engine, no ranking and no machine learning behind it. Rules
without the field still work (the alert just has an empty recommendation).

**13. Do you use machine learning, or a chatbot?**
No. Detection is purely rule-based and explainable: every alert can be traced to one
rule and the events that matched it. ML anomaly detection and a chatbot assistant are
listed as **future work** only.

**14. How does it compare with Chainsaw or Hayabusa?**
I have **not** measured that yet - neither tool was installed, so I do not claim any
result. `compare_tools.py` and [comparison_template.md](comparison_template.md) are
prepared for it. Qualitatively: those tools have thousands of Sigma rules and are
much faster (Rust); my project covers 4 techniques with 16 rules but every part is
small enough to explain.

**15. What are the main limitations, and how could an attacker evade it?**
Only EVTX files (no live monitoring, no Sysmon/Linux). Rules are keyword-based, so
renaming a binary or avoiding the listed keywords evades them; legitimate admin tools
can cause false positives. Thresholds are fixed numbers, so a slow attack below the
threshold (e.g. 4 tries every 10 minutes) is not detected. Detection depends on the
audit policy (no 4698 if auditing is off). Correlation keeps relevant events in memory.
The evaluation set is small and has no normal background traffic, so the real
false-positive rate is unknown.
