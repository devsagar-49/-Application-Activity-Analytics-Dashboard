# Project C – Application Activity Analytics Dashboard

A Python + Streamlit educational security analytics dashboard for **synthetic application activity logs**.

## Features

- CSV log parsing and validation
- Total events, success count, error count and error rate
- Average and median duration
- Module-wise analytics
- Filters for module, status and event type
- Rule-based anomaly flags
- Three visualizations
- Filtered log display
- Downloadable incident summary CSV
- Downloadable filtered logs CSV
- Security and ethics statement
- Basic logging

## Required CSV columns

```text
timestamp,module,event_type,status,duration_ms
```

## Detection rules

A module is flagged when:

- Error rate > 10%, OR
- Average duration > 1000 ms

A flagged pattern is **not proof of a cyber attack**.

## Run on Windows

Open Command Prompt in this project folder:

```bash
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
streamlit run app.py
```

If `streamlit` is not recognized, use:

```bash
python -m streamlit run app.py
```

The browser should open the local dashboard automatically. If it does not, open the local URL shown in the terminal.

## Demo flow

1. Show the problem statement.
2. Show `data/activity_logs.csv`.
3. Start the dashboard.
4. Explain the KPI cards.
5. Demonstrate module/status/event filters.
6. Show all three charts.
7. Show flagged modules.
8. Explain the threshold rules.
9. Download the incident summary.
10. Upload a CSV with a missing column or invalid timestamp to demonstrate validation.
11. Explain security, ethics and limitations.

## Security and ethics

Use only synthetic data. Do not add real passwords, account identifiers, secrets, private IP information or other sensitive data.

This is an educational rule-based analytics prototype, not a production intrusion-detection system.
