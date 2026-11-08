import glob
import yaml


def load_rules(rules_dir="rules"):
    """يقرأ كل ملفات YAML (ويدعم أكثر من قاعدة بنفس الملف مفصولة بـ ---)"""
    rules = []
    for path in sorted(glob.glob(f"{rules_dir}/*.yml")):
        with open(path, encoding="utf-8") as f:
            for rule in yaml.safe_load_all(f):
                if rule:
                    rules.append(rule)
    return rules


def field_matches(value, op, expected):
    """يقارن قيمة حقل بالقيم المتوقعة (بدون حساسية لحالة الأحرف)"""
    if value is None:
        return False
    value = str(value).lower()
    expected = expected if isinstance(expected, list) else [expected]
    expected = [str(e).lower() for e in expected]

    if op == "contains":
        return any(e in value for e in expected)
    if op == "startswith":
        return any(value.startswith(e) for e in expected)
    if op == "endswith":
        return any(value.endswith(e) for e in expected)
    return any(value == e for e in expected)  # equals


def matches(rule, event):
    """هل الحدث يطابق شروط القاعدة؟"""
    det = rule.get("detection", {})

    if "event_id" in det and event["event_id"] not in det["event_id"]:
        return False
    if "channel" in det and event["channel"] != det["channel"]:
        return False

    # فلتر الحقول: كل حقل لازم يتحقق، والقيم داخل القائمة الواحدة (أو)
    for key, expected in det.get("fields", {}).items():
        name, _, op = key.partition("|")
        if not field_matches(event["data"].get(name), op or "equals", expected):
            return False
    return True


def run_detection(events, rules):
    """يطبق كل القواعد على كل الأحداث ويرجع التنبيهات"""
    alerts = []
    for event in events:
        for rule in rules:
            if matches(rule, event):
                details = {k: event["data"].get(k) for k in rule.get("show", [])}
                alerts.append({
                    "time": event["time"],
                    "computer": event["computer"],
                    "rule": rule["title"],
                    "level": rule["level"],
                    "mitre": rule["mitre"],
                    "details": details,
                })
    return alerts