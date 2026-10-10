import sys
from detector.parser import parse_evtx

path = sys.argv[1]
for i, event in enumerate(parse_evtx(path)):
    print(event)
    if i >= 4:   # اطبع أول 5 أحداث بس
        break