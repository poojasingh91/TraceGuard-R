
"""Evaluate TraceGuard-R when synthetic log records are missing."""

import random

import pandas as pd

from normalize import load_events
from correlate import correlate


def detects_scripted_scenario(events):
    """Check whether the known Alice authentication scenario is detected."""
    alerts = correlate(events)

    if alerts.empty:
        return False

    matches = alerts[
        (alerts["user"] == "alice")
        & (alerts["rule"] == "failed_logins_then_success")
    ]

    return not matches.empty


def run_missing_evidence_experiment(
    missing_rates=(0.0, 0.1, 0.3, 0.5),
    trials=100,
    seed=42,
):
    """Randomly remove records and measure detection of the scripted scenario."""
    original_events = load_events()
    rng = random.Random(seed)
    results = []

    for missing_rate in missing_rates:
        detected = 0

        for _ in range(trials):
            # Sample independently for each trial.
            keep_mask = [
                rng.random() >= missing_rate
                for _ in range(len(original_events))
            ]

            incomplete_events = (
                original_events.loc[keep_mask]
                .copy()
                .reset_index(drop=True)
            )

            if detects_scripted_scenario(incomplete_events):
                detected += 1

        results.append({
            "missing_rate": missing_rate,
            "trials": trials,
            "detections": detected,
            "detection_rate": detected / trials,
        })

    return pd.DataFrame(results)


def main():
    results = run_missing_evidence_experiment()

    print("\nTraceGuard-R: Missing-Evidence Experiment")
    print("Synthetic data only; results are not real-world performance.\n")

    display = results.copy()
    display["missing_rate"] = (
        display["missing_rate"] * 100
    ).map(lambda x: f"{x:.0f}%")
    display["detection_rate"] = (
        display["detection_rate"] * 100
    ).map(lambda x: f"{x:.1f}%")
    display = display.rename(columns={
        "missing_rate": "Records Missing",
        "trials": "Trials",
        "detections": "Successful Detections",
        "detection_rate": "Detection Rate",
    })

    print(display.to_string(index=False))

    results.to_csv(
        "missing_evidence_results.csv",
        index=False,
    )
    print("\nSaved results to missing_evidence_results.csv")


if __name__ == "__main__":
    main()
