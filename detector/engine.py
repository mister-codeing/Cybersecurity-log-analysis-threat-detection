import glob
import yaml


def load_rules(rules_dir="rules"):
    """يقرأ كل ملفات YAML من مجلد القواعد"""
    rules = []
    for path in glob.glob(f"{rules_dir}/*.yml"):
        with open(path, encoding="utf-8") as f:
            rule = yaml.safe_load(f)
            if rule:
                rules.append(rule)
    return rules


def matches(rule, event):
    """هل الحدث يطابق شروط القاعدة؟"""
    det = rule.get("detection", {})

    if "event_id" in det and event["event_id"] not in det["event_id"]:
        return False
    if "channel" in det and event["channel"] != det["channel"]:
        return False
    return True


def run_detection(events, rules):
    """يطبق كل القواعد على كل الأحداث ويرجع التنبيهات"""
    alerts = []
    for event in events:
        for rule in rules:
            if matches(rule, event):
                alerts.append({
                    "time": event["time"],
                    "computer": event["computer"],
                    "rule": rule["title"],
                    "level": rule["level"],
                    "mitre": rule["mitre"],
                })
    return alerts