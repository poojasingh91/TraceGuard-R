"""Generate labeled synthetic security logs for TraceGuard-R."""

from pathlib import Path
import random
import pandas as pd

OUT = Path(__file__).parent / "data"


def main():
    rng = random.Random(17)
    OUT.mkdir(parents=True, exist_ok=True)

    auth, network, system = [], [], []

    # Normal background activity.
    for i in range(30):
        minute = i * 7
        user = f"user{(i % 5) + 1}"
        host = f"workstation{(i % 6) + 1}"
        ip = f"10.0.1.{(i % 40) + 10}"
        timestamp = (
            pd.Timestamp("2026-10-10 08:00:00")
            + pd.Timedelta(minutes=minute)
        )

        auth.append({
            "event_id": f"A-N{i:03}",
            "timestamp": str(timestamp),
            "user": user,
            "source_ip": ip,
            "hostname": host,
            "event_type": "login_success",
            "success": True,
            "scenario_id": "normal_background",
            "ground_truth": "normal",
        })

        network.append({
            "event_id": f"N-N{i:03}",
            "timestamp": str(timestamp + pd.Timedelta(hours=1)),
            "user": user,
            "source_ip": ip,
            "source_host": host,
            "destination_ip": f"10.0.2.{(i % 15) + 10}",
            "destination_host": f"server{(i % 4) + 1}",
            "bytes_out": rng.randint(5000, 90000),
            "event_type": "connection",
            "scenario_id": "normal_background",
            "ground_truth": "normal",
        })

        system.append({
            "event_id": f"S-N{i:03}",
            "timestamp": str(
                timestamp
                + pd.Timedelta(hours=1, seconds=30)
            ),
            "user": user,
            "hostname": host,
            "process_name": "browser.exe",
            "event_type": "process_start",
            "file_path": "",
            "scenario_id": "normal_background",
            "ground_truth": "normal",
        })

    # Scenario A: suspicious authentication and subsequent activity.
    for i, seconds in enumerate([0, 30, 60], start=1):
        auth.append({
            "event_id": f"A-S00{i}",
            "timestamp": str(
                pd.Timestamp("2026-10-10 10:00:00")
                + pd.Timedelta(seconds=seconds)
            ),
            "user": "alice",
            "source_ip": "198.51.100.77",
            "hostname": "laptop-alice",
            "event_type": "login_failure",
            "success": False,
            "scenario_id": "scenario_alice",
            "ground_truth": "suspicious",
        })

    auth.append({
        "event_id": "A-S004",
        "timestamp": "2026-10-10 10:02:00",
        "user": "alice",
        "source_ip": "198.51.100.77",
        "hostname": "laptop-alice",
        "event_type": "login_success",
        "success": True,
        "scenario_id": "scenario_alice",
        "ground_truth": "suspicious",
    })

    network.extend([
        {
            "event_id": "N-S001",
            "timestamp": "2026-10-10 10:04:00",
            "user": "alice",
            "source_ip": "198.51.100.77",
            "source_host": "laptop-alice",
            "destination_ip": "10.0.2.50",
            "destination_host": "restricted-server",
            "bytes_out": 18000,
            "event_type": "connection",
            "scenario_id": "scenario_alice",
            "ground_truth": "suspicious",
        },
        {
            "event_id": "N-S002",
            "timestamp": "2026-10-10 10:06:00",
            "user": "alice",
            "source_ip": "198.51.100.77",
            "source_host": "restricted-server",
            "destination_ip": "203.0.113.88",
            "destination_host": "external-host",
            "bytes_out": 85000000,
            "event_type": "connection",
            "scenario_id": "scenario_alice",
            "ground_truth": "suspicious",
        },
    ])

    system.extend([
        {
            "event_id": "S-S001",
            "timestamp": "2026-10-10 10:04:30",
            "user": "alice",
            "hostname": "restricted-server",
            "process_name": "powershell.exe",
            "event_type": "process_start",
            "file_path": "",
            "scenario_id": "scenario_alice",
            "ground_truth": "suspicious",
        },
        {
            "event_id": "S-S002",
            "timestamp": "2026-10-10 10:05:00",
            "user": "alice",
            "hostname": "restricted-server",
            "process_name": "archive-tool.exe",
            "event_type": "file_access",
            "file_path": "C:/Sensitive/demo.zip",
            "scenario_id": "scenario_alice",
            "ground_truth": "suspicious",
        },
    ])

    # Scenario B: suspicious network activity, no login-failure sequence.
    network.append({
        "event_id": "N-B001",
        "timestamp": "2026-10-10 11:10:00",
        "user": "bob",
        "source_ip": "198.51.100.22",
        "source_host": "laptop-bob",
        "destination_ip": "203.0.113.25",
        "destination_host": "external-host",
        "bytes_out": 75000000,
        "event_type": "connection",
        "scenario_id": "scenario_bob",
        "ground_truth": "suspicious",
    })

    # Scenario C: suspicious system activity without network evidence.
    system.append({
        "event_id": "S-C001",
        "timestamp": "2026-10-10 11:20:00",
        "user": "carol",
        "hostname": "workstation-carol",
        "process_name": "unknown-demo-process.exe",
        "event_type": "suspicious_process",
        "file_path": "C:/Temp/demo_payload.bin",
        "scenario_id": "scenario_carol",
        "ground_truth": "suspicious",
    })

    # Scenario D: legitimate large transfer, deliberately labeled normal.
    network.append({
        "event_id": "N-D001",
        "timestamp": "2026-10-10 11:30:00",
        "user": "dave",
        "source_ip": "10.0.1.80",
        "source_host": "backup-server",
        "destination_ip": "10.0.3.20",
        "destination_host": "approved-backup",
        "bytes_out": 80000000,
        "event_type": "scheduled_backup",
        "scenario_id": "scenario_dave",
        "ground_truth": "normal",
    })

    pd.DataFrame(auth).to_csv(OUT / "auth_logs.csv", index=False)
    pd.DataFrame(network).to_csv(OUT / "network_logs.csv", index=False)
    pd.DataFrame(system).to_csv(OUT / "system_logs.csv", index=False)

    print(f"Wrote labeled synthetic logs to {OUT}")


if __name__ == "__main__":
    main()