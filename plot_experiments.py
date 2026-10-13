
import pandas as pd
import plotly.express as px

results = pd.read_csv("missing_evidence_results.csv")

results["missing_percent"] = results["missing_rate"] * 100
results["detection_percent"] = results["detection_rate"] * 100

fig = px.line(
    results,
    x="missing_percent",
    y="detection_percent",
    markers=True,
    title="TraceGuard-R Detection Rate Under Missing Evidence",
    labels={
        "missing_percent": "Records Missing (%)",
        "detection_percent": "Detection Rate (%)",
    },
)

fig.update_yaxes(range=[0, 100])
fig.show()
