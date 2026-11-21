# Comparison with Chainsaw and Hayabusa (template)

> **Status: NOT RUN YET.** Chainsaw and Hayabusa were not installed on the machine
> where this project was developed, so **no numbers from these tools exist in this
> repository**. Fill in the table below only with numbers you really produced.

## Why the numbers are not directly comparable

- Chainsaw (with Sigma) and Hayabusa ship **thousands** of rules; this project has 16
  rules for 4 techniques. More alerts does not mean "better".
- Hayabusa also reports *informational* events (e.g. every logon), Chainsaw groups
  some detections. Count what each tool calls a detection, and say so in the notes.
- A fairer comparison: for each sample, *did the tool detect the technique in the
  file name?* (yes / no), plus the raw alert count.

## Step 1 - create the CSV

```bash
python compare_tools.py --init output/comparison.csv
```

This writes one row per sample and tool (`output/` is git-ignored):

```csv
sample,tool,alerts,notes
DE_1102_security_log_cleared.evtx,chainsaw,,
DE_1102_security_log_cleared.evtx,hayabusa,,
...
```

## Step 2 - run the tools yourself

Chainsaw (<https://github.com/WithSecureLabs/chainsaw/releases>, Sigma rules from
<https://github.com/SigmaHQ/sigma>):

```bash
chainsaw hunt samples/DE_1102_security_log_cleared.evtx -s sigma/rules \
    --mapping mappings/sigma-event-logs-all.yml --json --output out.json
```

Count the entries in `out.json`, e.g. in Python:
`python -c "import json; print(len(json.load(open('out.json'))))"`.

Hayabusa (<https://github.com/Yamato-Security/hayabusa/releases>):

```bash
hayabusa csv-timeline -f samples/DE_1102_security_log_cleared.evtx -o out.csv
```

Count the rows of `out.csv` minus the header. Write the tool **version** and the
rule set / profile you used into the `notes` column.

## Step 3 - show the comparison

```bash
python compare_tools.py output/comparison.csv
```

The script runs **this** tool on every sample itself (real counts, default settings),
adds the numbers from your CSV, prints a Markdown table and writes it to
`output/comparison.md`. Empty cells are shown as `not filled` - never guessed.

If `chainsaw` is on your PATH, the script can run it for you and store only the
number of detections per sample:

```bash
python compare_tools.py output/comparison.csv --run-chainsaw \
    --sigma path/to/sigma/rules --mapping path/to/mappings/sigma-event-logs-all.yml
```

(This automatic path was written for the defence but could not be tested here,
because Chainsaw was not installed. If it fails for a sample, the cell stays empty
and the note says `chainsaw failed`.)

## Result table (fill in)

| Sample | Technique | evtx-detector alerts | detected? | Chainsaw alerts | detected? | Hayabusa alerts | detected? | Notes |
|---|---|---:|---|---:|---|---:|---|---|
| DE_1102_security_log_cleared.evtx | T1070.001 | | | | | | | |
| DE_104_system_log_cleared.evtx | T1070.001 | | | | | | | |
| LM_Remote_Service02_7045.evtx | T1543.003 | | | | | | | |
| System_7045_namedpipe_privesc.evtx | T1543.003 | | | | | | | |
| temp_scheduled_task_4698_4699.evtx | T1053.005 | | | | | | | |
| PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx | T1053.005 | | | | | | | |
| LM_ScheduledTask_ATSVC_target_host.evtx | T1053.005 | | | | | | | |
| kerberos_pwd_spray_4771.evtx | T1110 | | | | | | | |
| DE_RDP_Tunneling_4624.evtx | T1021.001 | | | | | | | |
| DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx | T1021.001 | | | | | | | |
| CA_4624_4625_LogonType2_LogonProc_chrome.evtx | none (negative) | | | | | | | |

Tool versions used: Chainsaw `____`, Sigma rules commit `____`, Hayabusa `____`, date `____`.
