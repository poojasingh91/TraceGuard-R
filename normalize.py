"""Load heterogeneous sources into one event schema while retaining original fields."""
from pathlib import Path
import pandas as pd

DATA_DIR = Path(__file__).parent / "data"

def load_events(data_dir=DATA_DIR):
    frames = []
    for filename, source in [
        ("auth_logs.csv", "authentication"),
        ("network_logs.csv", "network"),
        ("system_logs.csv", "system"),
    ]:
        path = Path(data_dir) / filename
        if not path.exists():
            raise FileNotFoundError(f"Missing {path}. Run: python generate_data.py")
        df = pd.read_csv(path, dtype={"event_id": "string"})
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        df["source"] = source
        df["event_id"] = df["event_id"].astype(str)
        for col in ["user", "source_ip", "hostname", "source_host",
                    "destination_ip", "destination_host", "event_type"]:
            if col not in df:
                df[col] = ""
            df[col] = df[col].fillna("").astype(str)
        if "bytes_out" not in df:
            df["bytes_out"] = 0
        df["bytes_out"] = pd.to_numeric(df["bytes_out"], errors="coerce").fillna(0)
        frames.append(df)
    events = pd.concat(frames, ignore_index=True, sort=False)
    events = events.dropna(subset=["timestamp"]).sort_values("timestamp")
    return events.reset_index(drop=True)
