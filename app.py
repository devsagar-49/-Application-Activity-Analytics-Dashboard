import io
import logging
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

# -----------------------------
# Configuration / Logging
# -----------------------------
logging.basicConfig(
    filename="dashboard.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

REQUIRED_COLUMNS = [
    "timestamp",
    "module",
    "event_type",
    "status",
    "duration_ms",
]

MAX_DURATION_MS = 60_000
ERROR_RATE_THRESHOLD = 20.0
DURATION_THRESHOLD_MS = 1000


# -----------------------------
# Page configuration
# -----------------------------
st.set_page_config(
    page_title="Application Activity Analytics",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Application Activity Analytics Dashboard")
st.caption(
    "Rule-based analytics for synthetic application activity logs. "
    "A flagged pattern is NOT proof of a cyber attack."
)


# -----------------------------
# Data loading and validation
# -----------------------------
@st.cache_data
def load_csv(file_bytes: bytes) -> pd.DataFrame:
    return pd.read_csv(io.BytesIO(file_bytes))


def validate_and_clean(raw_df: pd.DataFrame):
    df = raw_df.copy()
    errors = []
    warnings = []

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        errors.append("Missing required columns: " + ", ".join(missing))
        return None, errors, warnings

    # Keep only the expected columns for predictable processing.
    df = df[REQUIRED_COLUMNS].copy()

    if df.empty:
        errors.append("The CSV file is empty.")
        return None, errors, warnings

    # Timestamp validation
    original_timestamp = df["timestamp"].copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    invalid_ts = int(df["timestamp"].isna().sum())

    if invalid_ts:
        warnings.append(
            f"{invalid_ts} row(s) have invalid timestamps and were removed."
        )
        df = df.dropna(subset=["timestamp"])

    # Duration validation
    df["duration_ms"] = pd.to_numeric(df["duration_ms"], errors="coerce")
    invalid_duration = int(df["duration_ms"].isna().sum())
    if invalid_duration:
        warnings.append(
            f"{invalid_duration} row(s) have invalid duration values and were removed."
        )
        df = df.dropna(subset=["duration_ms"])

    negative_duration = int((df["duration_ms"] < 0).sum())
    if negative_duration:
        warnings.append(
            f"{negative_duration} row(s) have negative duration and were removed."
        )
        df = df[df["duration_ms"] >= 0]

    extreme_duration = int((df["duration_ms"] > MAX_DURATION_MS).sum())
    if extreme_duration:
        warnings.append(
            f"{extreme_duration} row(s) exceed {MAX_DURATION_MS:,} ms. "
            "They are retained but flagged as extreme."
        )

    # Basic text normalization
    for col in ["module", "event_type", "status"]:
        df[col] = df[col].astype(str).str.strip()

    df["status"] = df["status"].str.upper()

    # Only known statuses are accepted for the main metrics.
    known_statuses = {"SUCCESS", "ERROR"}
    unknown_status = ~df["status"].isin(known_statuses)
    unknown_count = int(unknown_status.sum())
    if unknown_count:
        warnings.append(
            f"{unknown_count} row(s) contain a status other than SUCCESS/ERROR."
        )

    df = df.sort_values("timestamp").reset_index(drop=True)

    if df.empty:
        errors.append("No valid records remain after validation.")
        return None, errors, warnings

    return df, errors, warnings


# -----------------------------
# Analytics
# -----------------------------
def calculate_metrics(df: pd.DataFrame):
    total_events = len(df)
    error_count = int((df["status"] == "ERROR").sum())
    success_count = int((df["status"] == "SUCCESS").sum())
    error_rate = (error_count / total_events * 100) if total_events else 0
    avg_duration = float(df["duration_ms"].mean()) if total_events else 0
    median_duration = float(df["duration_ms"].median()) if total_events else 0

    return {
        "total_events": total_events,
        "error_count": error_count,
        "success_count": success_count,
        "error_rate": error_rate,
        "avg_duration": avg_duration,
        "median_duration": median_duration,
    }


def module_analysis(df: pd.DataFrame) -> pd.DataFrame:
    result = (
        df.groupby("module")
        .agg(
            total_events=("status", "count"),
            error_count=("status", lambda x: int((x == "ERROR").sum())),
            avg_duration_ms=("duration_ms", "mean"),
            median_duration_ms=("duration_ms", "median"),
        )
        .reset_index()
    )

    result["error_rate"] = (
        result["error_count"] / result["total_events"] * 100
    ).round(2)

    result["duration_flag"] = result["avg_duration_ms"] > DURATION_THRESHOLD_MS
    result["error_flag"] = result["error_rate"] > ERROR_RATE_THRESHOLD
    result["flagged"] = result["duration_flag"] | result["error_flag"]

    result["reason"] = result.apply(
        lambda row: (
            "High error rate + high average duration"
            if row["error_flag"] and row["duration_flag"]
            else "High error rate"
            if row["error_flag"]
            else "High average duration"
            if row["duration_flag"]
            else "Normal"
        ),
        axis=1,
    )

    return result.sort_values(
        ["flagged", "error_rate"], ascending=[False, False]
    ).reset_index(drop=True)


def add_record_flags(df: pd.DataFrame) -> pd.DataFrame:
    result = df.copy()
    result["duration_flag"] = result["duration_ms"] > DURATION_THRESHOLD_MS
    result["extreme_duration"] = result["duration_ms"] > MAX_DURATION_MS
    result["record_flag"] = result["duration_flag"]
    return result


# -----------------------------
# Sidebar
# -----------------------------
st.sidebar.header("⚙️ Settings")
st.sidebar.write("Detection rules")
st.sidebar.info(
    f"Error-rate threshold: > {ERROR_RATE_THRESHOLD:.0f}%\n\n"
    f"Duration threshold: > {DURATION_THRESHOLD_MS:,} ms\n\n"
    f"Extreme duration: > {MAX_DURATION_MS:,} ms"
)

uploaded_file = st.sidebar.file_uploader(
    "Upload a CSV log file",
    type=["csv"],
    help="CSV must contain timestamp, module, event_type, status and duration_ms.",
)

default_path = "data/activity_logs.csv"

if uploaded_file is not None:
    source_name = uploaded_file.name
    raw = load_csv(uploaded_file.getvalue())
else:
    source_name = default_path
    try:
        with open(default_path, "rb") as f:
            raw = load_csv(f.read())
    except FileNotFoundError:
        st.error(
            "Default dataset not found. Put activity_logs.csv inside the data folder."
        )
        st.stop()

df, errors, warnings = validate_and_clean(raw)

for message in warnings:
    st.warning("⚠️ " + message)

if errors:
    for message in errors:
        st.error("❌ " + message)
    st.stop()

logger.info("Loaded dataset: %s | rows=%d", source_name, len(df))

metrics = calculate_metrics(df)
module_stats = module_analysis(df)
flagged_records = add_record_flags(df)


# -----------------------------
# KPI cards
# -----------------------------
st.subheader("📊 Summary Metrics")

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Events", f"{metrics['total_events']:,}")
c2.metric("Success", f"{metrics['success_count']:,}")
c3.metric("Errors", f"{metrics['error_count']:,}")
c4.metric("Error Rate", f"{metrics['error_rate']:.2f}%")
c5.metric("Avg Duration", f"{metrics['avg_duration']:.0f} ms")

c6, c7 = st.columns(2)
c6.metric("Median Duration", f"{metrics['median_duration']:.0f} ms")
c7.metric("Flagged Modules", f"{int(module_stats['flagged'].sum())}")


# -----------------------------
# Filters
# -----------------------------
st.subheader("🔎 Filters")

f1, f2, f3 = st.columns(3)

modules = ["All"] + sorted(df["module"].dropna().unique().tolist())
statuses = ["All"] + sorted(df["status"].dropna().unique().tolist())
event_types = ["All"] + sorted(df["event_type"].dropna().unique().tolist())

selected_module = f1.selectbox("Module", modules)
selected_status = f2.selectbox("Status", statuses)
selected_event = f3.selectbox("Event Type", event_types)

filtered = df.copy()

if selected_module != "All":
    filtered = filtered[filtered["module"] == selected_module]

if selected_status != "All":
    filtered = filtered[filtered["status"] == selected_status]

if selected_event != "All":
    filtered = filtered[filtered["event_type"] == selected_event]

st.caption(f"Showing {len(filtered):,} record(s) after filtering.")


# -----------------------------
# Charts
# -----------------------------
st.subheader("📈 Visual Analytics")

chart1, chart2 = st.columns(2)

with chart1:
    counts = df["module"].value_counts().sort_values()
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh(counts.index, counts.values)
    ax.set_title("Events by Module")
    ax.set_xlabel("Number of Events")
    ax.set_ylabel("Module")
    fig.tight_layout()
    st.pyplot(fig)
    plt.close(fig)

with chart2:
    status_counts = df["status"].value_counts()
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(status_counts.index, status_counts.values)
    ax.set_title("Status Distribution")
    ax.set_xlabel("Status")
    ax.set_ylabel("Number of Events")
    fig.tight_layout()
    st.pyplot(fig)
    plt.close(fig)

fig, ax = plt.subplots(figsize=(10, 4))
plot_data = module_stats.sort_values("error_rate")
ax.bar(plot_data["module"], plot_data["error_rate"])
ax.axhline(
    ERROR_RATE_THRESHOLD,
    linestyle="--",
    label=f"Threshold ({ERROR_RATE_THRESHOLD:.0f}%)",
)
ax.set_title("Error Rate by Module")
ax.set_xlabel("Module")
ax.set_ylabel("Error Rate (%)")
ax.legend()
plt.xticks(rotation=25, ha="right")
fig.tight_layout()
st.pyplot(fig)
plt.close(fig)


# -----------------------------
# Module analysis table
# -----------------------------
st.subheader("🚦 Module Analysis")

display_stats = module_stats.copy()
display_stats["avg_duration_ms"] = display_stats["avg_duration_ms"].round(2)
display_stats["median_duration_ms"] = display_stats["median_duration_ms"].round(2)
display_stats["error_rate"] = display_stats["error_rate"].map(
    lambda x: f"{x:.2f}%"
)
display_stats["flagged"] = display_stats["flagged"].map(
    lambda x: "⚠️ FLAGGED" if x else "✅ NORMAL"
)

st.dataframe(display_stats, use_container_width=True)


# -----------------------------
# Flagged activity
# -----------------------------
st.subheader("⚠️ Flagged Activity")

flagged_modules = module_stats[module_stats["flagged"]].copy()

if flagged_modules.empty:
    st.success("No module crossed the configured anomaly thresholds.")
else:
    st.warning(
        "These are rule-based unusual patterns. They are not proof of an attack."
    )
    st.dataframe(
        flagged_modules,
        use_container_width=True,
    )


# -----------------------------
# Filtered records
# -----------------------------
st.subheader("📋 Filtered Records")

filtered_display = filtered.copy()
filtered_display["timestamp"] = filtered_display["timestamp"].dt.strftime(
    "%Y-%m-%d %H:%M:%S"
)

st.dataframe(
    filtered_display,
    use_container_width=True,
    height=320,
)


# -----------------------------
# Incident summary download
# -----------------------------
st.subheader("⬇️ Incident Summary Report")

incident_report = module_stats[
    [
        "module",
        "total_events",
        "error_count",
        "error_rate",
        "avg_duration_ms",
        "median_duration_ms",
        "flagged",
        "reason",
    ]
].copy()

incident_report["avg_duration_ms"] = incident_report["avg_duration_ms"].round(2)
incident_report["median_duration_ms"] = incident_report[
    "median_duration_ms"
].round(2)

csv_report = incident_report.to_csv(index=False).encode("utf-8")

st.download_button(
    label="Download Incident Summary CSV",
    data=csv_report,
    file_name="incident_summary.csv",
    mime="text/csv",
)

st.download_button(
    label="Download Filtered Logs CSV",
    data=filtered.to_csv(index=False).encode("utf-8"),
    file_name="filtered_activity_logs.csv",
    mime="text/csv",
)


# -----------------------------
# Security / limitations
# -----------------------------
st.subheader("🔐 Security & Ethics")

st.markdown(
    """
- The dataset is **synthetic** and should not contain real IP addresses, account IDs,
  passwords, secrets, or other sensitive information.
- The dashboard performs **rule-based anomaly detection**, not full intrusion detection.
- A flagged pattern is **not proof of a cyber attack**.
- Thresholds should be tuned using legitimate application baselines.
- The dashboard does not automatically fetch or open arbitrary URLs.
"""
)

with st.expander("ℹ️ Detection Logic & Limitations"):
    st.write(
        f"""
        A module is flagged when either:
        1. its error rate is greater than {ERROR_RATE_THRESHOLD:.0f}%, or
        2. its average duration is greater than {DURATION_THRESHOLD_MS:,} ms.

        These simple rules can produce false positives and false negatives.
        They are intended for educational analytics and demonstration, not for
        production security monitoring.
        """
    )

st.caption(
    "Project C | Application Activity Analytics Dashboard | "
    "Synthetic data only"
)
