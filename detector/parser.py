import Evtx.Evtx as evtx
import xmltodict


def parse_evtx(path):
    """يقرأ ملف EVTX ويرجع كل حدث كـ dictionary موحد"""
    with evtx.Evtx(path) as log:
        for record in log.records():
            try:
                event = xmltodict.parse(record.xml())["Event"]
            except Exception:
                continue  # تجاهل السجلات التالفة
            yield normalize(event)


def normalize(event):
    """يحول الحدث لصيغة بسيطة"""
    system = event["System"]

    eid = system["EventID"]
    eid = int(eid["#text"] if isinstance(eid, dict) else eid)

    data = {}

    # أغلب الأحداث تخزن بياناتها بـ EventData
    raw = (event.get("EventData") or {}).get("Data", [])
    if isinstance(raw, dict):
        raw = [raw]
    for item in raw or []:
        if item and item.get("@Name"):
            data[item["@Name"]] = item.get("#text")

    # بعض الأحداث (مثل 1102 و104) تخزن بياناتها بـ UserData
    user_data = event.get("UserData") or {}
    for child in user_data.values():
        if isinstance(child, dict):
            for key, value in child.items():
                if not key.startswith("@"):
                    data[key] = value if isinstance(value, str) else str(value)

    return {
        "event_id": eid,
        "time": system["TimeCreated"]["@SystemTime"],
        "channel": system.get("Channel"),
        "computer": system.get("Computer"),
        "data": data,
    }