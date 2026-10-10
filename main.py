import sys
from detector.parser import parse_evtx
from detector.engine import load_rules, run_detection

path = sys.argv[1]
rules = load_rules()
print(f"[*] Loaded {len(rules)} rule(s)")

alerts = run_detection(parse_evtx(path), rules)

for a in alerts:
    print(f"[{a['level'].upper()}] {a['time']} | {a['computer']} | "
          f"{a['rule']} ({a['mitre']})")

print(f"[*] Total alerts: {len(alerts)}")