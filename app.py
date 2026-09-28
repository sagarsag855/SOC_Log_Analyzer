import streamlit as st
import pandas as pd
from pathlib import Path

from src.database import (
    get_alerts,
    get_incidents,
    update_alert_status,
    update_incident_status,
    get_incident_statistics,
    initialize_incident_table
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="SOC Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

initialize_incident_table()

DB_FILE = "data/soc.db"
LOG_FILE = "data/security.log"


# ============================================================
# LOAD ALERTS
# ============================================================

def load_alerts():

    alerts = get_alerts()

    columns = [
        "alert_id",
        "type",
        "severity",
        "risk_score",
        "username",
        "ip_address",
        "count",
        "first_seen",
        "last_seen",
        "message",
        "status"
    ]

    return pd.DataFrame(
        alerts,
        columns=columns
    )


# ============================================================
# LOAD INCIDENTS
# ============================================================

def load_incidents():

    incidents = get_incidents()

    columns = [
        "incident_id",
        "title",
        "severity",
        "risk_score",
        "related_alerts",
        "status",
        "created_at",
        "updated_at"
    ]

    return pd.DataFrame(
        incidents,
        columns=columns
    )


# ============================================================
# LOAD DATA
# ============================================================

alerts_df = load_alerts()
incidents_df = load_incidents()
incident_stats = get_incident_statistics()


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ SOC Log Analyzer")

st.caption(
    "Security Operations Center — Threat Detection & Incident Management"
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.header("SOC Filters")

if not alerts_df.empty:

    severity_options = sorted(
        alerts_df["severity"].dropna().unique()
    )

    selected_severity = st.sidebar.multiselect(
        "Severity",
        severity_options,
        default=severity_options
    )

    ip_options = sorted(
        alerts_df["ip_address"].dropna().unique()
    )

    selected_ips = st.sidebar.multiselect(
        "IP Address",
        ip_options,
        default=ip_options
    )

    filtered_alerts = alerts_df[
        alerts_df["severity"].isin(selected_severity)
        &
        alerts_df["ip_address"].isin(selected_ips)
    ]

else:

    filtered_alerts = alerts_df


# ============================================================
# TOP METRICS
# ============================================================

total_alerts = len(filtered_alerts)

high_risk = len(
    filtered_alerts[
        filtered_alerts["severity"] == "HIGH"
    ]
)

medium_risk = len(
    filtered_alerts[
        filtered_alerts["severity"] == "MEDIUM"
    ]
)

average_risk = (
    filtered_alerts["risk_score"].mean()
    if not filtered_alerts.empty
    else 0
)

total_incidents = len(incidents_df)

open_incidents = (
    len(
        incidents_df[
            incidents_df["status"] == "Open"
        ]
    )
    if not incidents_df.empty
    else 0
)


col1, col2, col3, col4, col5, col6 = st.columns(6)

col1.metric(
    "Total Alerts",
    total_alerts
)

col2.metric(
    "High Risk",
    high_risk
)

col3.metric(
    "Medium Risk",
    medium_risk
)

col4.metric(
    "Avg Risk",
    f"{average_risk:.2f}"
)

col5.metric(
    "Incidents",
    total_incidents
)

col6.metric(
    "Open Incidents",
    open_incidents
)


# ============================================================
# SOC INCIDENT KPIs
# ============================================================

st.markdown("## 🛡️ SOC Incident KPIs")

kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)

kpi1.metric(
    "Total Incidents",
    incident_stats["total"]
)

kpi2.metric(
    "High Risk",
    incident_stats["high"]
)

kpi3.metric(
    "Open",
    incident_stats["open"]
)

kpi4.metric(
    "Investigating",
    incident_stats["investigating"]
)

kpi5.metric(
    "Resolved",
    incident_stats["resolved"]
)

kpi6.metric(
    "Avg Risk",
    f"{incident_stats['average_risk']:.1f}"
)


# ============================================================
# TABS
# ============================================================

tabs = st.tabs([
    "📊 Overview",
    "🚨 Alerts",
    "🔎 Investigation",
    "🌐 Threat Analysis",
    "⏱️ Timeline",
    "📜 Event Logs",
    "📄 Incident Report",
    "🚑 Incident Management",
    "🧠 Detection Rules"
])


# ============================================================
# OVERVIEW
# ============================================================

with tabs[0]:

    st.subheader("Security Overview")

    if filtered_alerts.empty:

        st.info("No alerts match the selected filters.")

    else:

        col1, col2 = st.columns(2)

        with col1:

            st.markdown("### Severity Distribution")

            severity_chart = (
                filtered_alerts["severity"]
                .value_counts()
            )

            st.bar_chart(severity_chart)

        with col2:

            st.markdown("### Incident Status")

            if not incidents_df.empty:

                status_chart = (
                    incidents_df["status"]
                    .value_counts()
                )

                st.bar_chart(status_chart)

            else:

                st.info("No incidents available.")


# ============================================================
# ALERTS
# ============================================================

with tabs[1]:

    st.subheader("Security Alerts")

    if filtered_alerts.empty:

        st.info("No alerts available.")

    else:

        display_columns = [
            "alert_id",
            "type",
            "severity",
            "risk_score",
            "username",
            "ip_address",
            "count",
            "first_seen",
            "last_seen",
            "status"
        ]

        st.dataframe(
            filtered_alerts[display_columns],
            use_container_width=True,
            hide_index=True
        )


# ============================================================
# INVESTIGATION
# ============================================================

with tabs[2]:

    st.subheader("Alert Investigation")

    if filtered_alerts.empty:

        st.info("No alerts available for investigation.")

    else:

        alert_options = filtered_alerts[
            "alert_id"
        ].tolist()

        selected_alert_id = st.selectbox(
            "Select Alert",
            alert_options
        )

        selected_alert = filtered_alerts[
            filtered_alerts["alert_id"]
            == selected_alert_id
        ].iloc[0]

        st.markdown("### Alert Details")

        col1, col2 = st.columns(2)

        with col1:

            st.write(
                "**Alert ID:**",
                selected_alert["alert_id"]
            )

            st.write(
                "**Type:**",
                selected_alert["type"]
            )

            st.write(
                "**Severity:**",
                selected_alert["severity"]
            )

            st.write(
                "**Risk Score:**",
                selected_alert["risk_score"]
            )

            st.write(
                "**Username:**",
                selected_alert["username"]
            )

        with col2:

            st.write(
                "**IP Address:**",
                selected_alert["ip_address"]
            )

            st.write(
                "**Count:**",
                selected_alert["count"]
            )

            st.write(
                "**First Seen:**",
                selected_alert["first_seen"]
            )

            st.write(
                "**Last Seen:**",
                selected_alert["last_seen"]
            )

        st.write(
            "**Message:**",
            selected_alert["message"]
        )

        st.markdown("### Update Alert Status")

        current_status = selected_alert["status"]

        status_options = [
            "Open",
            "Investigating",
            "Resolved"
        ]

        new_status = st.selectbox(
            "Status",
            status_options,
            index=(
                status_options.index(current_status)
                if current_status in status_options
                else 0
            )
        )

        if st.button("Update Alert Status"):

            update_alert_status(
                selected_alert_id,
                new_status
            )

            st.success(
                "Alert status updated successfully."
            )

            st.rerun()


# ============================================================
# THREAT ANALYSIS
# ============================================================

with tabs[3]:

    st.subheader("Threat Analysis")

    if filtered_alerts.empty:

        st.info("No threat data available.")

    else:

        col1, col2 = st.columns(2)

        with col1:

            st.markdown("### Alerts by IP")

            ip_chart = (
                filtered_alerts["ip_address"]
                .value_counts()
                .head(10)
            )

            st.bar_chart(ip_chart)

        with col2:

            st.markdown("### Threat Types")

            threat_chart = (
                filtered_alerts["type"]
                .value_counts()
                .head(10)
            )

            st.bar_chart(threat_chart)

        st.markdown("### High-Risk IP Addresses")

        high_risk_ips = (
            filtered_alerts[
                filtered_alerts["severity"] == "HIGH"
            ]
            .groupby("ip_address")
            .agg(
                Alerts=("alert_id", "count"),
                Maximum_Risk=("risk_score", "max")
            )
            .sort_values(
                "Maximum_Risk",
                ascending=False
            )
        )

        st.dataframe(
            high_risk_ips,
            use_container_width=True
        )


# ============================================================
# TIMELINE
# ============================================================

with tabs[4]:

    st.subheader("Security Alert Timeline")

    timeline_df = filtered_alerts.copy()

    if timeline_df.empty:

        st.info("No timeline data available.")

    else:

        timeline_df["first_seen"] = pd.to_datetime(
            timeline_df["first_seen"],
            errors="coerce"
        )

        timeline_df = timeline_df.dropna(
            subset=["first_seen"]
        )

        timeline = (
            timeline_df
            .groupby("first_seen")
            .size()
        )

        st.line_chart(timeline)

        st.dataframe(
            timeline_df[
                [
                    "alert_id",
                    "type",
                    "severity",
                    "first_seen",
                    "last_seen"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )


# ============================================================
# EVENT LOGS
# ============================================================

with tabs[5]:

    st.subheader("Raw Security Event Logs")

    log_path = Path(LOG_FILE)

    if log_path.exists():

        with open(
            log_path,
            "r",
            encoding="utf-8"
        ) as file:

            raw_logs = file.readlines()

        st.code(
            "".join(raw_logs),
            language="text"
        )

    else:

        st.warning(
            "Security log file not found."
        )


# ============================================================
# INCIDENT REPORT
# ============================================================

with tabs[6]:

    st.subheader("Incident Report")

    if filtered_alerts.empty:

        st.info(
            "No alerts available for the report."
        )

    else:

        report_lines = []

        report_lines.append(
            "SOC INCIDENT REPORT"
        )

        report_lines.append(
            "=" * 60
        )

        report_lines.append("")

        report_lines.append(
            f"Total Alerts: {len(filtered_alerts)}"
        )

        report_lines.append(
            f"High Risk: {high_risk}"
        )

        report_lines.append(
            f"Medium Risk: {medium_risk}"
        )

        report_lines.append(
            f"Average Risk Score: {average_risk:.2f}"
        )

        report_lines.append("")

        report_lines.append(
            "SECURITY ALERTS"
        )

        report_lines.append(
            "-" * 60
        )

        for _, alert in filtered_alerts.iterrows():

            report_lines.append("")

            report_lines.append(
                f"Alert ID: {alert['alert_id']}"
            )

            report_lines.append(
                f"Type: {alert['type']}"
            )

            report_lines.append(
                f"Severity: {alert['severity']}"
            )

            report_lines.append(
                f"Risk Score: {alert['risk_score']}"
            )

            report_lines.append(
                f"Username: {alert['username']}"
            )

            report_lines.append(
                f"IP Address: {alert['ip_address']}"
            )

            report_lines.append(
                f"First Seen: {alert['first_seen']}"
            )

            report_lines.append(
                f"Last Seen: {alert['last_seen']}"
            )

            report_lines.append(
                f"Status: {alert['status']}"
            )

            report_lines.append(
                f"Message: {alert['message']}"
            )

        report = "\n".join(report_lines)

        st.text_area(
            "Generated Report",
            report,
            height=500
        )

        st.download_button(
            "Download Incident Report",
            report,
            file_name="soc_incident_report.txt",
            mime="text/plain"
        )


# ============================================================
# INCIDENT MANAGEMENT
# ============================================================

with tabs[7]:

    st.subheader("Incident Management")

    if incidents_df.empty:

        st.info("No incidents available.")

    else:

        incident_col1, incident_col2, incident_col3 = st.columns(3)

        incident_col1.metric(
            "Total Incidents",
            len(incidents_df)
        )

        incident_col2.metric(
            "Open",
            len(
                incidents_df[
                    incidents_df["status"] == "Open"
                ]
            )
        )

        incident_col3.metric(
            "High Severity",
            len(
                incidents_df[
                    incidents_df["severity"] == "HIGH"
                ]
            )
        )

        st.markdown("### Incident List")

        st.dataframe(
            incidents_df,
            use_container_width=True,
            hide_index=True
        )

        st.markdown("### Incident Details")

        incident_ids = incidents_df[
            "incident_id"
        ].tolist()

        selected_incident_id = st.selectbox(
            "Select Incident",
            incident_ids
        )

        # FIX:
        # The incident variable is created inside the
        # same else block where it is used.

        incident = incidents_df[
            incidents_df["incident_id"]
            == selected_incident_id
        ].iloc[0]

        col1, col2 = st.columns(2)

        with col1:

            st.write(
                "**Incident ID:**",
                incident["incident_id"]
            )

            st.write(
                "**Title:**",
                incident["title"]
            )

            st.write(
                "**Severity:**",
                incident["severity"]
            )

            st.write(
                "**Risk Score:**",
                incident["risk_score"]
            )

        with col2:

            st.write(
                "**Related Alerts:**",
                incident["related_alerts"]
            )

            st.write(
                "**Status:**",
                incident["status"]
            )

            st.write(
                "**Created:**",
                incident["created_at"]
            )

            st.write(
                "**Updated:**",
                incident["updated_at"]
            )

        st.markdown("### Update Incident Status")

        incident_status_options = [
            "Open",
            "Investigating",
            "Resolved"
        ]

        current_incident_status = incident["status"]

        new_incident_status = st.selectbox(
            "Incident Status",
            incident_status_options,
            index=(
                incident_status_options.index(
                    current_incident_status
                )
                if current_incident_status
                in incident_status_options
                else 0
            )
        )

        if st.button(
            "Update Incident Status"
        ):

            update_incident_status(
                int(incident["incident_id"]),
                new_incident_status
            )

            st.success(
                "Incident status updated successfully."
            )

            st.rerun()


# ============================================================
# DETECTION RULES
# ============================================================

with tabs[8]:

    st.subheader("🧠 Detection Rules")

    st.caption(
        "Rules currently implemented in the SOC detection engine."
    )

    detection_rules = pd.DataFrame([

        {
            "Rule ID": "AUTH-001",
            "Detection": "Repeated Failed Login",
            "Condition": "3+ failed logins from same IP within 5 minutes",
            "Severity": "HIGH",
            "Risk Score": 80
        },

        {
            "Rule ID": "AUTH-002",
            "Detection": "Successful Login After Failed Attempts",
            "Condition": "Successful login after 3+ recent failures",
            "Severity": "MEDIUM",
            "Risk Score": 50
        },

        {
            "Rule ID": "AUTH-003",
            "Detection": "Multiple Usernames from One IP",
            "Condition": "3+ usernames observed from one IP",
            "Severity": "MEDIUM",
            "Risk Score": 50
        },

        {
            "Rule ID": "AUTH-004",
            "Detection": "Rapid Brute-Force Activity",
            "Condition": "5+ failed logins within 2 minutes",
            "Severity": "HIGH",
            "Risk Score": 90
        },

        {
            "Rule ID": "AUTH-005",
            "Detection": "Unusual Login Time",
            "Condition": "Successful login before 06:00 or from 23:00",
            "Severity": "MEDIUM",
            "Risk Score": 50
        },

        {
            "Rule ID": "AUTH-006",
            "Detection": "Same User from Multiple IPs",
            "Condition": "Same user successfully logs in from 2+ IPs",
            "Severity": "MEDIUM",
            "Risk Score": 50
        },

        {
            "Rule ID": "AUTH-007",
            "Detection": "Login After Long Inactivity",
            "Condition": "8+ hours since previous successful login",
            "Severity": "MEDIUM",
            "Risk Score": 50
        },

        {
            "Rule ID": "CORR-001",
            "Detection": "Multiple Security Alerts from Same IP",
            "Condition": "2+ different detection rules from one IP",
            "Severity": "HIGH",
            "Risk Score": 90
        },

        {
            "Rule ID": "CORR-002",
            "Detection": "Multiple High-Risk Alerts from Same IP",
            "Condition": "2+ HIGH alerts from one IP",
            "Severity": "HIGH",
            "Risk Score": 100
        }

    ])

    st.dataframe(
        detection_rules,
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "SOC Log Analyzer | Python • SQLite • Pandas • Streamlit"
)