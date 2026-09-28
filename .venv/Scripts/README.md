# SOC Log Analyzer & Threat Detection Dashboard

A Python-based Security Operations Center (SOC) tool that analyzes authentication logs, detects suspicious activities, assigns risk scores, stores security alerts in SQLite, and provides an interactive Streamlit dashboard for investigation and incident management.

## Project Overview

The SOC Log Analyzer processes security event logs and automatically identifies suspicious authentication behavior using predefined detection rules.

The project combines:

- Python
- Pandas
- SQLite
- Streamlit
- Rule-based threat detection
- Security alert correlation
- Incident management
- Risk scoring
- Interactive dashboards

## Architecture

Security Logs
      |
      v
Log Parser
      |
      v
Event Normalization
      |
      v
Detection Engine
      |
      v
Threat Classification
      |
      +------------------+
      |                  |
      v                  v
Risk Scoring       Alert Correlation
      |                  |
      +--------+---------+
               |
               v
            SQLite
               |
               v
       Streamlit Dashboard
               |
       +-------+-------+
       |               |
       v               v
 Investigation    Incident Management

## Detection Rules

| Rule ID | Detection | Severity | Risk |
|---|---|---|---:|
| AUTH-001 | Repeated Failed Login | HIGH | 80 |
| AUTH-002 | Successful Login After Failed Attempts | MEDIUM | 50 |
| AUTH-003 | Multiple Usernames from One IP | MEDIUM | 50 |
| AUTH-004 | Rapid Brute-Force Activity | HIGH | 90 |
| AUTH-005 | Unusual Login Time | MEDIUM | 50 |
| AUTH-006 | Same User from Multiple IPs | MEDIUM | 50 |
| AUTH-007 | Login After Long Inactivity | MEDIUM | 50 |
| CORR-001 | Multiple Security Alerts from Same IP | HIGH | 90 |
| CORR-002 | Multiple High-Risk Alerts from Same IP | HIGH | 100 |

## Dashboard Features

The Streamlit dashboard provides:

- SOC overview
- Security alert monitoring
- Severity analysis
- Risk-score analysis
- IP-based threat analysis
- Timeline analysis
- Raw event log inspection
- Alert investigation
- Incident reports
- Incident management
- Incident status tracking
- Detection rule documentation
- CSV incident export

## Incident Management

The system groups related security alerts into incidents.

Incident statuses include:

- Open
- Investigating
- Resolved

The dashboard provides incident statistics including:

- Total incidents
- High-risk incidents
- Open incidents
- Investigating incidents
- Resolved incidents
- Average incident risk

## Risk Scoring

The system assigns risk scores based on detected threat severity.

Example:

- MEDIUM = 50
- HIGH = 80 or above
- Correlation-based threats can reach 100

The risk score helps prioritize security events for investigation.

## Technology Stack

### Programming Language

Python 3.12

### Data Processing

Pandas

### Database

SQLite

### Dashboard

Streamlit

### Development Environment

Visual Studio Code

## Project Structure

```text
SOC_Log_Analyzer/
│
├── .gitignore
├── requirements.txt
├── README.md
├── app.py
├── main.py
│
├── data/
│   └── security.log
│
└── src/
    ├── __init__.py
    ├── database.py
    └── detector.py