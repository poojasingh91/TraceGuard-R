"""Transparent, evidence-linked detection rules for synthetic security events."""
import pandas as pd

LARGE_TRANSFER_BYTES = 50_000_000
CORRELATION_WINDOW_MINUTES = 15

def correlate(events: pd.DataFrame) -> pd.DataFrame:
    alerts = []
    auth = events[events["source"] == "authentication"].copy()
    net = events[events["source"] == "network"].copy()
    sys = events[events["source"] == "system"].copy()

    # Rule 1: multiple failed logins followed by success for same user and source IP.
    for (user, ip), group in auth.groupby(["user", "source_ip"], dropna=False):
        group = group.sort_values("timestamp")
        failures = group[group["event_type"].str.lower().eq("login_failure")]
        successes = group[group["event_type"].str.lower().eq("login_success")]
        for _, success in successes.iterrows():
            prior = failures[
                (failures["timestamp"] < success["timestamp"]) &
                (failures["timestamp"] >= success["timestamp"] - pd.Timedelta(minutes=10))
            ]
            if len(prior) >= 3:
                evidence = list(prior["event_id"]) + [success["event_id"]]
                alerts.append({
                    "alert_id": f"TG-AUTH-{success['event_id']}",
                    "start_time": prior["timestamp"].min(),
                    "end_time": success["timestamp"],
                    "user": user, "source_ip": ip,
                    "destination_host": success.get("hostname", ""),
                    "severity": "high", "rule": "failed_logins_then_success",
                    "title": "Repeated login failures followed by success",
                    "observed_facts": f"{len(prior)} failed login records preceded a successful login within 10 minutes.",
                    "inference": "This pattern may indicate password guessing or a user having trouble signing in.",
                    "evidence_ids": evidence,
                })

    # Rule 2: unusually large outbound transfer.
    for _, event in net[net["bytes_out"] >= LARGE_TRANSFER_BYTES].iterrows():
        alerts.append({
            "alert_id": f"TG-NET-{event['event_id']}",
            "start_time": event["timestamp"], "end_time": event["timestamp"],
            "user": event.get("user", ""), "source_ip": event.get("source_ip", ""),
            "destination_host": event.get("destination_host", ""),
            "severity": "high" if event["bytes_out"] >= 100_000_000 else "medium",
            "rule": "large_outbound_transfer",
            "title": "Large outbound transfer",
            "observed_facts": f"One network record reports {int(event['bytes_out']):,} outbound bytes.",
            "inference": "The volume may warrant investigation; volume alone does not establish data exfiltration.",
            "evidence_ids": [event["event_id"]],
        })

    # Rule 3: connect auth -> network -> system evidence by user and nearby time.
    # This is a candidate relationship, not proof that one event caused another.
    for _, success in auth[auth["event_type"].str.lower().eq("login_success")].iterrows():
        nearby_net = net[
            (net["user"] == success["user"]) &
            (net["timestamp"] >= success["timestamp"]) &
            (net["timestamp"] <= success["timestamp"] + pd.Timedelta(minutes=CORRELATION_WINDOW_MINUTES))
        ]
        for _, connection in nearby_net.iterrows():
            nearby_sys = sys[
                (sys["user"] == success["user"]) &
                (sys["timestamp"] >= success["timestamp"]) &
                (sys["timestamp"] <= connection["timestamp"] + pd.Timedelta(minutes=2)) &
                (sys["timestamp"] >= connection["timestamp"] - pd.Timedelta(minutes=2))
            ]
            if len(nearby_sys) and (
                connection["bytes_out"] >= LARGE_TRANSFER_BYTES or
                "restricted" in str(connection.get("destination_host", "")).lower()
            ):
                evidence = [success["event_id"], connection["event_id"]] + list(nearby_sys["event_id"])
                aid = f"TG-CHAIN-{success['event_id']}-{connection['event_id']}"
                if not any(a["alert_id"] == aid for a in alerts):
                    alerts.append({
                        "alert_id": aid, "start_time": success["timestamp"],
                        "end_time": max(connection["timestamp"], nearby_sys["timestamp"].max()),
                        "user": success["user"], "source_ip": success["source_ip"],
                        "destination_host": connection.get("destination_host", ""),
                        "severity": "medium", "rule": "cross_source_sequence",
                        "title": "Cross-source activity sequence",
                        "observed_facts": "Authentication, network, and system records share a user and fall within the configured time window.",
                        "inference": "These records may be related; shared user and timing are not sufficient to prove causality.",
                        "evidence_ids": evidence,
                    })

    columns = ["alert_id","start_time","end_time","user","source_ip","destination_host",
               "severity","rule","title","observed_facts","inference","evidence_ids"]
    result = pd.DataFrame(alerts, columns=columns)
    if not result.empty:
        result = result.sort_values("start_time").reset_index(drop=True)
    return result
