"""Small smoke evaluation against the scripted synthetic scenario."""
from normalize import load_events
from correlate import correlate

def main():
    events = load_events()
    alerts = correlate(events)
    print(f"Events loaded: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    if alerts.empty:
        print("No alerts. Check the synthetic data and detection rules.")
    else:
        print(alerts[["alert_id", "severity", "title", "user", "evidence_ids"]].to_string(index=False))
    print("\nReminder: this is a smoke test, not a statistically meaningful evaluation.")

if __name__ == "__main__":
    main()
