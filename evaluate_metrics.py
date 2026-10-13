"""Preliminary user-level evaluation using independent synthetic labels."""

import pandas as pd

from normalize import load_events
from correlate import correlate


def calculate_metrics(events, alerts):
    if "ground_truth" not in events.columns:
        raise ValueError(
            "Ground-truth labels are missing. "
            "Run the updated generate_data.py."
        )

    # Each user is suspicious if any of their labeled records
    # belongs to a suspicious scenario.
    user_truth = (
        events.assign(
            is_suspicious=events["ground_truth"].eq("suspicious")
        )
        .groupby("user")["is_suspicious"]
        .any()
        .to_dict()
    )

    alert_users = set()
    if not alerts.empty:
        alert_users = set(alerts["user"].dropna().astype(str))

    rows = []
    for user, actual in sorted(user_truth.items()):
        predicted = user in alert_users

        if actual and predicted:
            outcome = "TP"
        elif not actual and predicted:
            outcome = "FP"
        elif actual and not predicted:
            outcome = "FN"
        else:
            outcome = "TN"

        rows.append({
            "user": user,
            "ground_truth": "suspicious" if actual else "normal",
            "predicted": "suspicious" if predicted else "normal",
            "outcome": outcome,
        })

    evaluation = pd.DataFrame(rows)
    counts = evaluation["outcome"].value_counts()

    tp = int(counts.get("TP", 0))
    fp = int(counts.get("FP", 0))
    fn = int(counts.get("FN", 0))
    tn = int(counts.get("TN", 0))

    def ratio(a, b):
        return a / b if b else 0.0

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2 * precision * recall, precision + recall)
    fpr = ratio(fp, fp + tn)

    metrics = {
        "users_evaluated": len(evaluation),
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
    }

    return evaluation, metrics


def main():
    events = load_events()
    alerts = correlate(events)
    evaluation, metrics = calculate_metrics(events, alerts)

    print("\nTraceGuard-R: Multi-Scenario User Evaluation")
    print("Synthetic data only; not real-world performance.\n")
    print(evaluation.to_string(index=False))

    print("\nMetrics:")
    for key, value in metrics.items():
        if key in {"precision", "recall", "f1", "false_positive_rate"}:
            print(f"{key}: {value:.3f}")
        else:
            print(f"{key}: {value}")

    evaluation.to_csv("user_evaluation_results.csv", index=False)
    pd.DataFrame([metrics]).to_csv("evaluation_metrics.csv", index=False)


if __name__ == "__main__":
    main()