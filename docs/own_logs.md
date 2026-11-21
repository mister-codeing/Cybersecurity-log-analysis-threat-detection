# Testing with your own logs (small real brute-force test)

The public samples contain no real password-guessing burst, so brute force is
only tested with synthetic events. This guide shows how to create a **small,
real** brute-force test on **your own Windows PC**, with a throw-away test account.

> **Privacy warning.** An exported Security log contains your user names, computer
> name, SIDs, IP addresses and the times you used the PC. **Never commit it, never
> upload it to a public place, and delete it when you are done.**
> `*.evtx` and `my_logs/` are in `.gitignore` - keep it that way, and check
> `git status` before every commit.

Only do this on a computer that you own or are allowed to test. All commands below
need an **elevated** prompt (right-click *Terminal* → *Run as administrator*).

## 1. Check that failed logons are audited

```powershell
auditpol /get /subcategory:"Logon"
```

It should say `Success and Failure`. If not:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

## 2. Create a test account

```powershell
net user bftest Test-Only-Pass1! /add
```

## 3. Produce a few failed logons, then one success

Windows 11 locks an account after 10 wrong passwords by default, so stay below that:

1. Run `runas /user:bftest cmd` and type a **wrong** password - repeat **6 times**
   within a few minutes (each try writes event 4625, LogonType 2).
2. Run it once more with the **correct** password (event 4624) and close the new window.

Expected with default settings (5 failures in 10 minutes):
`rule-007` (Brute Force - Multiple Failed Logons, medium). `rule-008` (critical) also
needs the success to come from the same `IpAddress` as the failures - for local
`runas` logons Windows usually writes the same local value for both, but check
your own result rather than assuming it.

## 4. Export only the last hour of the Security log

```powershell
mkdir my_logs
wevtutil epl Security my_logs\bf_test.evtx /q:"*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]"
```

`epl` = export log; the query keeps only events of the last 3 600 000 ms (1 hour),
so the file is small and contains less private data. Your live log is not changed.

## 5. Analyse it

```powershell
python main.py my_logs\bf_test.evtx
python main.py my_logs\bf_test.evtx --format html --output output   # report for screenshots
```

Write down what you saw (number of 4625 events, which rules fired). If you want to
mention it in the defence, describe it as "a manual test on my own PC", not as part
of the automatic evaluation - the file is not in the repository, so nobody else can
re-run it.

## 6. Clean up

```powershell
net user bftest /delete
Remove-Item -Recurse my_logs        # when you no longer need the file
```
