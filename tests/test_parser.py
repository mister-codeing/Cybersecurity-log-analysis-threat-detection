"""Tests for detector/parser.py - turning event XML into normalized dicts."""

import xmltodict

from detector.parser import normalize, normalize_time, parse_time


def to_event(xml: str) -> dict:
    """Parse an <Event> XML string exactly like parse_evtx() does."""
    return xmltodict.parse(xml)["Event"]


FAILED_LOGON_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2024-01-01T10:00:00.1234567Z"/>
    <EventRecordID>42</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DC01.lab.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">bob</Data>
    <Data Name="IpAddress">10.0.0.5</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="SubStatus"/>
  </EventData>
</Event>
"""

SERVICE_XML = """
<Event>
  <System>
    <EventID Qualifiers="16384">7045</EventID>
    <TimeCreated SystemTime="2024-01-01 10:00:00.500000+00:00"/>
    <Channel>System</Channel>
    <Computer>PC01</Computer>
  </System>
  <EventData>
    <Data Name="ServiceName">evil</Data>
    <Data Name="ImagePath">C:\\Users\\Public\\evil.exe</Data>
  </EventData>
</Event>
"""

LOG_CLEARED_XML = """
<Event>
  <System>
    <EventID>1102</EventID>
    <TimeCreated SystemTime="2024-01-01T10:00:00Z"/>
    <Channel>Security</Channel>
    <Computer>PC01</Computer>
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserName>attacker</SubjectUserName>
      <SubjectDomainName>LAB</SubjectDomainName>
    </LogFileCleared>
  </UserData>
</Event>
"""


def test_normalize_eventdata_fields():
    event = normalize(to_event(FAILED_LOGON_XML))
    assert event["event_id"] == 4625
    assert event["channel"] == "Security"
    assert event["computer"] == "DC01.lab.local"
    assert event["provider"] == "Microsoft-Windows-Security-Auditing"
    assert event["record_id"] == 42
    assert event["data"]["TargetUserName"] == "bob"
    assert event["data"]["IpAddress"] == "10.0.0.5"
    assert event["data"]["SubStatus"] is None          # empty <Data/> -> None


def test_normalize_time_with_seven_digits_and_z():
    event = normalize(to_event(FAILED_LOGON_XML))
    assert event["time"] == "2024-01-01T10:00:00.123456+00:00"


def test_normalize_event_id_with_qualifiers():
    event = normalize(to_event(SERVICE_XML))
    assert event["event_id"] == 7045
    assert event["time"] == "2024-01-01T10:00:00.500000+00:00"
    assert event["data"]["ImagePath"] == "C:\\Users\\Public\\evil.exe"


def test_normalize_userdata():
    event = normalize(to_event(LOG_CLEARED_XML))
    assert event["event_id"] == 1102
    assert event["data"] == {"SubjectUserName": "attacker", "SubjectDomainName": "LAB"}


def test_normalize_single_and_unnamed_data_items():
    xml = """<Event><System><EventID>1</EventID></System>
             <EventData><Data>first</Data><Data>second</Data></EventData></Event>"""
    event = normalize(to_event(xml))
    assert event["data"] == {"param1": "first", "param2": "second"}

    xml_single = """<Event><System><EventID>1</EventID></System>
                    <EventData><Data Name="Only">x</Data></EventData></Event>"""
    assert normalize(to_event(xml_single))["data"] == {"Only": "x"}


def test_normalize_missing_parts_does_not_crash():
    event = normalize(to_event("<Event><System><EventID>5</EventID></System></Event>"))
    assert event["event_id"] == 5
    assert event["time"] is None
    assert event["data"] == {}


def test_parse_time_formats():
    assert parse_time(None) is None
    assert parse_time("not a date") is None
    assert parse_time("2024-01-01T10:00:00Z").hour == 10
    # Times without a timezone are treated as UTC.
    assert normalize_time("2024-01-01 10:00:00") == "2024-01-01T10:00:00+00:00"
