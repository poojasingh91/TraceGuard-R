# TraceGuard-R

Evidence-grounded cyber incident reconstruction prototype.

## Scope
TraceGuard-R correlates synthetic authentication, network, and system records. Alerts are investigative leads, not proof of compromise. The prototype keeps original source records and labels observed facts separately from inferred relationships.

## Quick start (Windows PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python generate_data.py
pytest -q
streamlit run app.py
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again.

## Data
`generate_data.py` creates deterministic synthetic records in `data/`. Do not use real sensitive logs in this demo. The synthetic data contains a scripted suspicious sequence and normal background activity.

## Research direction
Evaluate independent-source rules against cross-source correlation under controlled missing records and timestamp offsets. Report precision, recall, F1, false-positive rate, and reconstruction accuracy. Do not claim improvement until measured.

## Safety and interpretation
- A rule match is not proof of an attack.
- The `evidence_ids` field links each alert to source records.
- Relationships inferred from shared identifiers and time windows are not direct observations.
- Use only data you are authorized to analyze.
