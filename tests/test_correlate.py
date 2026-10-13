import sys
from pathlib import Path

# Add the project root to Python's import path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from generate_data import main as generate_data
from normalize import load_events
from correlate import correlate


def test_scripted_auth_sequence_is_detected():
    generate_data()

    events = load_events()
    alerts = correlate(events)

    auth_alerts = alerts[
        alerts["rule"] == "failed_logins_then_success"
    ]

    assert not auth_alerts.empty
    assert "alice" in auth_alerts["user"].tolist()


def test_large_transfer_rule_is_detected():
    generate_data()

    events = load_events()
    alerts = correlate(events)

    assert "large_outbound_transfer" in set(alerts["rule"])