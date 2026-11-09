"""Shared test helpers. Tests use small hand-made events, not real EVTX files."""

import os

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
SAMPLES_DIR = os.path.join(PROJECT_ROOT, "samples")


def build_event(event_id, minute=0, second=0, channel="Security",
                computer="PC01", **data):
    """Create a normalized event like parser.normalize() would return.

    'minute'/'second' set the time (2024-01-01 10:MM:SS UTC) so correlation
    tests can easily place events inside or outside a time window.
    """
    return {
        "event_id": event_id,
        "time": f"2024-01-01T10:{minute:02d}:{second:02d}+00:00",
        "channel": channel,
        "computer": computer,
        "provider": "Test-Provider",
        "record_id": 1,
        "data": data,
    }


@pytest.fixture
def make_event():
    return build_event
