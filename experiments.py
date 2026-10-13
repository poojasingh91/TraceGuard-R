
"""Evaluate TraceGuard-R when synthetic log records are missing."""

import pandas as pd

from normalize import load_events
from correlate import correlate


def evaluate_condition(events, condition):
    """Run detection and record which parts of the scripted chain survive."""
    alerts = correlate(events)

    alice_alerts = (
        alerts[alerts["user"].astype(str).str.lower() == "alice"]
        if not alerts.empty
        else alerts
    )

    detected_rules = set(alice_alerts["rule"].tolist())

    auth_detected = (
        "failed_logins_then_success" in detected_rules
    )
    network_detected = (
        "large_outbound_transfer" in detected_rules
    )
    cross_source_detected = (
        "cross_source_sequence" in detected_rules
    )

    return {
        "condition": condition,
        "events_remaining": len(events),
        "auth_detection": auth_detected,
        "large_transfer_detection": network_detected,
        "cross_source_detection": cross_source_detected,
        "complete_chain_detected": (
            auth_detected
            and network_detected
            and cross_source_detected
        ),
        "total_alice_alerts": len(alice_alerts),
    }


def run_source_ablation_experiment():
    """Compare full evidence with one-source-at-a-time removal."""
    original_events = load_events()

    required_sources = {"authentication", "network", "system"}
    available_sources = set(original_events["source"].dropna().unique())
    missing_sources = required_sources - available_sources

    if missing_sources:
        raise ValueError(
            f"Missing expected event sources: {sorted(missing_sources)}. "
            "Check normalize.py and your generated CSV files."
        )

    conditions = [
        ("full_evidence", None),
        ("without_authentication", "authentication"),
        ("without_network", "network"),
        ("without_system", "system"),
    ]

    results = []

    for condition, removed_source in conditions:
        if removed_source is None:
            test_events = original_events.copy()
        else:
            test_events = original_events[
                original_events["source"] != removed_source
            ].copy()

        results.append(
            evaluate_condition(test_events, condition)
        )

    return pd.DataFrame(results)


def main():
    results = run_source_ablation_experiment()

    print("\nTraceGuard-R: Evidence-Source Ablation")
    print("Synthetic data only; not real-world performance.\n")

    print(results.to_string(index=False))

    results.to_csv(
        "source_ablation_results.csv",
        index=False,
    )
    print("\nSaved results to source_ablation_results.csv")


if __name__ == "__main__":
    main()
