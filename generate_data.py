"""Generate deterministic synthetic logs for TraceGuard-R. No real telemetry is used."""
from pathlib import Path
import random
import pandas as pd

OUT = Path(__file__).parent / "data"
random.seed(17)

def main():
    OUT.mkdir(exist_ok=True)
    auth, network, system = [], [], []
    # Normal background activity
    for i in range(30):
        minute = i * 7
        user = f"user{(i % 5) + 1}"
        host = f"workstation{(i % 6) + 1}"
        ip = f"10.0.1.{(i % 40) + 10}"
        auth.append({
            "event_id": f"A-N{i:03}", "timestamp": f"2026-10-10 08:{minute % 60:02}:00",
            "user": user, "source_ip": ip, "hostname": host,
            "event_type": "login_success", "success": True
        })
        network.append({
            "event_id": f"N-N{i:03}", "timestamp": f"2026-10-10 09:{minute % 60:02}:00",
            "user": user, "source_ip": ip, "source_host": host,
            "destination_ip": f"10.0.2.{(i % 15) + 10}",
            "destination_host": f"server{(i % 4) + 1}",
            "bytes_out": random.randint(5000, 90000), "event_type": "connection"
        })
        system.append({
            "event_id": f"S-N{i:03}", "timestamp": f"2026-10-10 09:{minute % 60:02}:30",
            "user": user, "hostname": host, "process_name": "browser.exe",
            "event_type": "process_start", "file_path": ""
        })

    # Scripted scenario: repeated failures, successful login, sensitive host access,
    # then a large outbound transfer. This is a labeled synthetic scenario, not proof.
    auth.extend([
        {"event_id":"A-S001","timestamp":"2026-10-10 10:00:00","user":"alice","source_ip":"198.51.100.77","hostname":"laptop-alice","event_type":"login_failure","success":False},
        {"event_id":"A-S002","timestamp":"2026-10-10 10:00:30","user":"alice","source_ip":"198.51.100.77","hostname":"laptop-alice","event_type":"login_failure","success":False},
        {"event_id":"A-S003","timestamp":"2026-10-10 10:01:00","user":"alice","source_ip":"198.51.100.77","hostname":"laptop-alice","event_type":"login_failure","success":False},
        {"event_id":"A-S004","timestamp":"2026-10-10 10:02:00","user":"alice","source_ip":"198.51.100.77","hostname":"laptop-alice","event_type":"login_success","success":True},
    ])
    network.extend([
        {"event_id":"N-S001","timestamp":"2026-10-10 10:04:00","user":"alice","source_ip":"198.51.100.77","source_host":"laptop-alice","destination_ip":"10.0.2.50","destination_host":"restricted-server","bytes_out":18000,"event_type":"connection"},
        {"event_id":"N-S002","timestamp":"2026-10-10 10:06:00","user":"alice","source_ip":"198.51.100.77","source_host":"restricted-server","destination_ip":"203.0.113.88","destination_host":"external-host","bytes_out":85000000,"event_type":"connection"},
    ])
    system.extend([
        {"event_id":"S-S001","timestamp":"2026-10-10 10:04:30","user":"alice","hostname":"restricted-server","process_name":"powershell.exe","event_type":"process_start","file_path":""},
        {"event_id":"S-S002","timestamp":"2026-10-10 10:05:00","user":"alice","hostname":"restricted-server","process_name":"archive-tool.exe","event_type":"file_access","file_path":"C:/Sensitive/demo.zip"},
    ])

    pd.DataFrame(auth).to_csv(OUT / "auth_logs.csv", index=False)
    pd.DataFrame(network).to_csv(OUT / "network_logs.csv", index=False)
    pd.DataFrame(system).to_csv(OUT / "system_logs.csv", index=False)
    print(f"Wrote synthetic logs to {OUT}")

if __name__ == "__main__":
    main()
