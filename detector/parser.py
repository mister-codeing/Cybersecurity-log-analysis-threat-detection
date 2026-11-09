"""
parser.py - Read Windows EVTX files and turn every record into a simple dict.

Every event produced by this module has the same "normalized" shape, so the
rest of the program never has to deal with raw Windows XML:

    {
        "event_id":  4625,                         # int
        "time":      "2019-03-19T23:35:07.524200+00:00",  # ISO 8601, UTC
        "channel":   "Security",                   # log name
        "computer":  "PC01.example.corp",          # host that wrote the event
        "provider":  "Microsoft-Windows-Security-Auditing",
        "record_id": 1234,                         # position inside the file
        "data":      {"TargetUserName": "bob", "IpAddress": "10.0.0.5", ...},
    }
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator

import Evtx.Evtx as evtx
import xmltodict


def parse_evtx(path: str) -> Iterator[dict]:
    """Yield one normalized event dict for every record in an EVTX file.

    Damaged records are skipped so that one bad record does not stop the
    whole file. If the file itself cannot be opened (missing, empty, not an
    EVTX file) the exception is raised to the caller, who decides what to do.
    """
    with evtx.Evtx(path) as log:
        for record in log.records():
            try:
                event = xmltodict.parse(record.xml())["Event"]
                yield normalize(event)
            except Exception:
                continue  # skip a corrupt / unreadable record


def normalize(event: dict) -> dict:
    """Convert one event (as parsed by xmltodict) into our simple format."""
    system = event.get("System") or {}

    return {
        "event_id": _event_id(system.get("EventID")),
        "time": normalize_time((system.get("TimeCreated") or {}).get("@SystemTime")),
        "channel": system.get("Channel"),
        "computer": system.get("Computer"),
        "provider": (system.get("Provider") or {}).get("@Name"),
        "record_id": _to_int(system.get("EventRecordID")),
        "data": _event_data(event),
    }


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _event_id(raw: Any) -> int | None:
    """EventID is either "4625" or {"@Qualifiers": "16384", "#text": "7045"}."""
    if isinstance(raw, dict):
        raw = raw.get("#text")
    return _to_int(raw)


def normalize_time(raw: str | None) -> str | None:
    """Return the timestamp as an ISO 8601 string in UTC.

    python-evtx gives "2019-03-19 23:35:07.524200+00:00", while raw Windows XML
    uses "2019-03-19T23:35:07.5242000Z" (7 decimal digits). Both become
    "2019-03-19T23:35:07.524200+00:00" so that times can be compared and sorted.
    """
    dt = parse_time(raw)
    return dt.isoformat() if dt else raw


def parse_time(raw: str | None) -> datetime | None:
    """Turn a timestamp string into a timezone-aware datetime (or None)."""
    if not raw:
        return None
    text = str(raw).strip().replace("T", " ").replace("Z", "+00:00")

    # Python only understands up to 6 fractional digits -> cut the rest.
    if "." in text:
        main, rest = text.split(".", 1)
        digits = "".join(ch for ch in rest if ch.isdigit())
        tz = rest[len(digits):]
        text = f"{main}.{digits[:6]}{tz}"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:          # Windows event times are always UTC
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _text(value: Any) -> str | None:
    """Get the text of an XML value. <X/> -> None, <X a="1">t</X> -> "t"."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value.get("#text")
    return str(value)


def _event_data(event: dict) -> dict:
    """Collect the event's fields from <EventData> and/or <UserData>."""
    data: dict[str, str | None] = {}

    # 1) Most events: <EventData><Data Name="X">value</Data>...</EventData>
    event_data = event.get("EventData")
    if isinstance(event_data, dict):
        items = event_data.get("Data") or []
        if not isinstance(items, list):
            items = [items]
        for index, item in enumerate(items):
            if isinstance(item, dict) and item.get("@Name"):
                data[item["@Name"]] = item.get("#text")
            elif item is not None:
                # Some providers write <Data>value</Data> without a Name.
                data[f"param{index + 1}"] = _text(item)

    # 2) Some events (1102, 104, TerminalServices 21/22/25/1149) use
    #    <UserData><SomeElement><Field>value</Field>...</SomeElement></UserData>
    user_data = event.get("UserData")
    if isinstance(user_data, dict):
        for child in user_data.values():
            if not isinstance(child, dict):
                continue
            for key, value in child.items():
                if not key.startswith("@"):        # skip XML attributes
                    data[key] = _text(value)

    return data
