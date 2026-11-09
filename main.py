import sys
from detector.parser import parse_evtx
from detector.engine import load_rules, run_detection
from detector.correlation import load_config, run_correlation

path = sys.argv[1]
rules = load_rules()
print(f"[*] Loaded {len(rules)} rule(s)")

events = list(parse_evtx(path))
alerts = run_detection(events, rules) + run_correlation(events, rules, load_config("config.yml"))

for a in alerts:
    print(f"[{a['level'].upper()}] {a['time']} | {a['computer']} | "
          f"{a['rule']} ({a['mitre']})")
    for k, v in a["details"].items():
        print(f"        {k}: {v}")

print(f"[*] Total alerts: {len(alerts)}")
