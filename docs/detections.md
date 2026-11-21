# Detections

Four MITRE ATT&CK techniques, implemented by 16 rules in `rules/`.

## Summary table

| Rule id | Title | MITRE | Event ID(s) | Channel | Type | Level |
|---|---|---|---|---|---|---|
| rule-001 | Security Log Cleared | T1070.001 | 1102 | Security | single | high |
| rule-002 | Windows Log Cleared | T1070.001 | 104 | System | single | high |
| rule-003 | Suspicious Service Installed | T1543.003 | 7045 | System | single | high |
| rule-004 | Suspicious Service Installed (Security Log) | T1543.003 | 4697 | Security | single | high |
| rule-005 | Suspicious Scheduled Task Created | T1053.005 | 4698 | Security | single | high |
| rule-006 | Scheduled Task Registered | T1053.005 | 106 | TaskScheduler/Operational | single | low |
| rule-007 | Brute Force - Multiple Failed Logons | T1110 | 4625 | Security | threshold (5 / 10m per IpAddress) | medium |
| rule-008 | Brute Force Succeeded | T1110 | 4625 → 4624 | Security | sequence (5 / 10m per IpAddress) | critical |
| rule-009 | Kerberos Brute Force / Password Spray | T1110 | 4771 | Security | threshold (5 / 10m per IpAddress) | medium |
| rule-010 | NTLM Brute Force | T1110 | 4776 (Status ≠ 0x0) | Security | threshold (5 / 10m per Workstation) | medium |
| rule-011 | RDP Logon From Remote Address | T1021.001 | 4624 LogonType 10/12 | Security | single | low |
| rule-012 | RDP Authentication Succeeded | T1021.001 | 1149 | TerminalServices-RemoteConnectionManager/Operational | single | low |
| rule-013 | RDP Session Logon / Reconnect | T1021.001 | 21, 22, 25 | TerminalServices-LocalSessionManager/Operational | single | low |
| rule-014 | RDP Connection Received by Listener | T1021.001 | 261 | TerminalServices-RemoteConnectionManager/Operational | single | low |
| rule-015 | RDP - Same Account on Many Hosts | T1021.001 | 4624 LogonType 10/12 | Security | threshold (3 distinct computers / 60m per user) | high |
| rule-016 | RDP - Logons From Many Sources | T1021.001 | 4624 LogonType 10/12 | Security | threshold (3 distinct IPs / 60m per user) | medium |

## 1. Brute Force - T1110

**Idea:** a single failed logon is normal; many failures from one source in a
short time is password guessing. Many *different* usernames from one source is
password spraying - grouping by source IP catches both.

| Event | Meaning | Important fields |
|---|---|---|
| 4625 | An account failed to log on | `TargetUserName`, `IpAddress`, `LogonType`, `Status` |
| 4624 | An account successfully logged on | `TargetUserName`, `IpAddress`, `LogonType` |
| 4771 | Kerberos pre-authentication failed (domain controller) | `TargetUserName`, `IpAddress`, `Status` (0x18 = wrong password) |
| 4776 | NTLM credential validation (success **and** failure) | `TargetUserName`, `Workstation`, `Status` (0x0 = success) |

**Default thresholds:** 5 failures within 10 minutes. Reason: users rarely mistype
a password 5 times in a row, and 5 is close to common account-lockout policies.

**Severity escalation:** rule-008 is a *sequence*: ≥ 5 failures followed by a
successful 4624 from the same IP within 10 minutes → **critical**, because the
attacker probably has a valid password now. LogonType 0 (System) and
5 (Service) successes are excluded because they occur constantly.

## 2. Log Clearing - T1070.001

| Event | Meaning |
|---|---|
| 1102 (Security) | "The audit log was cleared" - written even when the Security log is wiped |
| 104 (System) | "The X log file was cleared" - for System, Application and other logs; `Channel` field names the log |

These are high-confidence: administrators rarely clear logs. rule-002 also
checks `provider = Microsoft-Windows-Eventlog`, because other providers reuse
ID 104 for unrelated events.

## 3. Persistence - T1543.003 (service) and T1053.005 (scheduled task)

| Event | Meaning | Field checked |
|---|---|---|
| 7045 (System) | A new service was installed | `ImagePath` |
| 4697 (Security) | A service was installed (needs "Audit Security System Extension") | `ServiceFileName` |
| 4698 (Security) | A scheduled task was created (needs "Audit Other Object Access Events") | `TaskContent` (task XML incl. command) |
| 106 (TaskScheduler/Operational) | A task was registered | none - no command in this event → low / informational |

Installing services and tasks is also normal software behaviour, so the rules only
alert when the command is suspicious:

| Indicator | Why it is suspicious |
|---|---|
| `\temp\`, `\appdata\`, `\users\public\`, `\programdata\` | user-writable folders, real software is installed in `Program Files` / `System32` |
| `powershell`, `cmd.exe`, `%comspec%` | a service/task that runs a shell is typical of PsExec-like tools and malware |
| `mshta`, `rundll32`, `regsvr32` | "living off the land" binaries used to run malicious code |
| ` -enc`, ` -ec `, `frombase64string` | encoded / obfuscated PowerShell commands |

## 4. Lateral Movement via RDP - T1021.001

| Event | Log | Meaning | Fields |
|---|---|---|---|
| 4624 LogonType 10 | Security | RemoteInteractive logon (RDP) | `TargetUserName`, `IpAddress` |
| 4624 LogonType 12 | Security | CachedRemoteInteractive (RDP with cached credentials) | same |
| 1149 | TerminalServices-RemoteConnectionManager/Operational | RDP user authentication succeeded | `Param1` user, `Param2` domain, `Param3` source IP |
| 261 | TerminalServices-RemoteConnectionManager/Operational | RDP listener received a connection | - |
| 21 / 22 / 25 | TerminalServices-LocalSessionManager/Operational | session logon / shell start / reconnection | `User`, `SessionID`, `Address` |

Single RDP events are **low** (RDP is often legitimate) - they document who
connected from where. Loopback/local addresses are excluded for 4624 and 21/22/25.
For 1149 they are kept because a `127.0.0.1` source can indicate RDP tunneling.

The lateral-movement **patterns** are correlation rules:

- **rule-015 (high):** the same account logs on via RDP to **≥ 3 different
  computers within 60 minutes** - typical of an attacker hopping between
  machines. Requires logs from several hosts analysed together.
- **rule-016 (medium):** the same account logs on via RDP from **≥ 3 different
  source IPs within 60 minutes** - unusual sources for one user.

## Recommendations

Every rule has an optional `recommendation:` - one or two sentences telling an
analyst what to check or do next (for example rule-008: treat the account as
compromised, disable it or reset its password, investigate the source IP and review
what happened after the successful logon). The text is written by hand in the rule,
copied into each alert and shown in all outputs. It is **not** generated or ranked by
any algorithm. See the rule files for the exact wording.

## Tuning

Edit `config.yml` (per rule id) or use `--threshold` / `--timeframe`
(applies to all correlation rules). To disable a rule, delete it or move the
YAML file out of `rules/`.
