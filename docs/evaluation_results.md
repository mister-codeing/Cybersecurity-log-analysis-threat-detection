# Evaluation results

> **Generated automatically** by `python evaluate.py` - do not edit by hand.
> Date: **2026-11-21 13:35:04 UTC** · Python **3.14.7** · python-evtx 0.8.1
> · Windows-11-10.0.26300-SP0

Ground truth: [`tests/expected_results.yml`](../tests/expected_results.yml) - written
from each sample's name and the EVTX-ATTACK-SAMPLES technique, **not** from this
tool's output. Processing times depend on the computer and change between runs.

## 1. Real samples (EVTX-ATTACK-SAMPLES), default settings

**Samples passed: 9/11** · Rule checks: TP = 8,
FN = 2, FP = 0 · 417 events in 1.018 s
(410 events/s)

| Result | File / scenario | Events | Time (s) | Expected | Actual | Missing (FN) | Unexpected (FP) | Allowed | Label |
|---|---|---:|---:|---|---|---|---|---|---|
| PASS | DE_1102_security_log_cleared.evtx | 112 | 0.318 | rule-001 | rule-001 | - | - | - | certain |
| PASS | DE_104_system_log_cleared.evtx | 1 | 0.004 | rule-002 | rule-002 | - | - | - | certain |
| PASS | LM_Remote_Service02_7045.evtx | 3 | 0.011 | rule-003 | rule-003 | - | - | - | certain |
| PASS | System_7045_namedpipe_privesc.evtx | 1 | 0.004 | rule-003 | rule-003 | - | - | - | certain |
| PASS | temp_scheduled_task_4698_4699.evtx | 2 | 0.008 | rule-005 | rule-005 | - | - | - | uncertain |
| PASS | PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx | 2 | 0.009 | rule-005 | rule-005 | - | - | - | uncertain |
| PASS | LM_ScheduledTask_ATSVC_target_host.evtx | 34 | 0.117 | rule-005 | rule-001, rule-005 | - | - | rule-001 | certain |
| **FAIL** | kerberos_pwd_spray_4771.evtx | 12 | 0.040 | rule-009 | rule-001 | rule-009 | - | rule-001 | uncertain |
| **FAIL** | DE_RDP_Tunneling_4624.evtx | 18 | 0.098 | rule-011 | - | rule-011 | - | - | uncertain |
| PASS | DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx | 228 | 0.386 | rule-012 | rule-012, rule-014 | - | - | rule-014 | certain |
| PASS | CA_4624_4625_LogonType2_LogonProc_chrome.evtx | 4 | 0.023 | - | - | - | - | - | uncertain |

### Per technique (real samples, default settings)

| Technique | Samples | Samples detected | TP | FN | FP |
|---|---:|---:|---:|---:|---:|
| T1021.001 | 2 | 1 | 1 | 1 | 0 |
| T1053.005 | 3 | 3 | 3 | 0 | 0 |
| T1070.001 | 2 | 2 | 2 | 0 | 0 |
| T1110 | 1 | 0 | 0 | 1 | 0 |
| T1543.003 | 2 | 2 | 2 | 0 | 0 |

TP = expected rule fired, FN = expected rule did not fire, FP = a rule fired that was
neither expected nor allowed. "Allowed" alerts (log clearing and rules of the same
technique, see the policy in `expected_results.yml`) are shown but not counted.

## 2. Real samples, tuned threshold (informational, not counted above)

| Result | File / scenario | Events | Time (s) | Expected | Actual | Missing (FN) | Unexpected (FP) | Allowed | Label |
|---|---|---:|---:|---|---|---|---|---|---|
| PASS | kerberos_pwd_spray_4771.evtx `[threshold=2]` | 12 | 0.037 | rule-009 | rule-001, rule-009 | - | - | rule-001 | uncertain |

## 3. SYNTHETIC scenarios (made-up events, not real logs)

**Passed: 8/8**. These events were written by hand in
`evaluate.py` to test the correlation logic on situations the public samples do not
contain. They prove the logic works as designed, not that it works on real attacks.

| Result | File / scenario | Events | Time (s) | Expected | Actual | Missing (FN) | Unexpected (FP) | Allowed | Label |
|---|---|---:|---:|---|---|---|---|---|---|
| PASS | Brute force: 8 failures in 8 min, then success | 9 | 0.000 | rule-007, rule-008 | rule-007, rule-008 | - | - | - | certain |
| PASS | Password spray: 6 users from one IP in 3 min | 6 | 0.000 | rule-007 | rule-007 | - | - | - | certain |
| PASS | NEGATIVE: 5 failures spread over 50 min (typos) | 5 | 0.000 | - | - | - | - | - | certain |
| PASS | NEGATIVE: 4 failures then success (below threshold) | 5 | 0.000 | - | - | - | - | - | certain |
| PASS | RDP lateral movement: 1 account -> 3 hosts in 30 min | 3 | 0.000 | rule-011, rule-015 | rule-011, rule-015 | - | - | - | certain |
| PASS | RDP from 3 source IPs to one host in 40 min | 3 | 0.000 | rule-011, rule-016 | rule-011, rule-016 | - | - | - | certain |
| PASS | NEGATIVE: normal RDP use (same host, same IP, 3 logons) | 3 | 0.000 | rule-011 | rule-011 | - | - | - | certain |
| PASS | NEGATIVE: 3 hosts but spread over 3 hours | 3 | 0.000 | rule-011 | rule-011 | - | - | - | certain |

## Samples skipped (not found locally)

- none

## Limitations of this evaluation

- **Very small sample set** (11 real files, mostly one technique each). The
  counts above are not a general detection rate or accuracy and must not be read as one.
- Ground truth is based on file names and technique descriptions; labels marked
  `uncertain` could be wrong (see the justification in `expected_results.yml`).
- Every sample is evaluated **on its own**, so correlation across several files
  (e.g. RDP to many hosts) is only tested with SYNTHETIC events.
- The samples are short lab recordings with no normal background activity, so the
  false-positive rate on a busy real network is **not** measured here.
