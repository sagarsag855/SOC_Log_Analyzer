import sqlite3
import hashlib


DB_FILE = "data/soc.db"


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def initialize_database():

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            fingerprint TEXT UNIQUE,
            type TEXT,
            severity TEXT,
            risk_score INTEGER,
            username TEXT,
            ip_address TEXT,
            count INTEGER,
            first_seen TEXT,
            last_seen TEXT,
            message TEXT,
            status TEXT DEFAULT 'Open'
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# SAVE ALERT
# ============================================================

def save_alert(alert):

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    fingerprint_data = (
        alert["alert_id"]
        + alert["username"]
        + alert["ip_address"]
        + str(alert["count"])
    )

    fingerprint = hashlib.sha256(
        fingerprint_data.encode()
    ).hexdigest()

    cursor.execute("""
        INSERT OR IGNORE INTO alerts (
            alert_id,
            fingerprint,
            type,
            severity,
            risk_score,
            username,
            ip_address,
            count,
            first_seen,
            last_seen,
            message,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["alert_id"],
        fingerprint,
        alert["type"],
        alert["severity"],
        alert["risk_score"],
        alert["username"],
        alert["ip_address"],
        alert["count"],
        alert["first_seen"],
        alert["last_seen"],
        alert["message"],
        "Open"
    ))

    connection.commit()
    connection.close()


# ============================================================
# GET ALERTS
# ============================================================

def get_alerts():

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            alert_id,
            type,
            severity,
            risk_score,
            username,
            ip_address,
            count,
            first_seen,
            last_seen,
            message,
            status
        FROM alerts
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts


# ============================================================
# UPDATE ALERT STATUS
# ============================================================

def update_alert_status(alert_id, status):

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        UPDATE alerts
        SET status = ?
        WHERE alert_id = ?
    """, (
        status,
        alert_id
    ))

    connection.commit()
    connection.close()

    # ============================================================
# INCIDENT MANAGEMENT
# ============================================================

def initialize_incident_table():

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            severity TEXT,
            risk_score INTEGER,
            related_alerts TEXT,
            status TEXT DEFAULT 'Open',
            created_at TEXT,
            updated_at TEXT
        )
    """)

    connection.commit()
    connection.close()

    # ============================================================
# CREATE INCIDENT
# ============================================================

def create_incident(
    title,
    severity,
    risk_score,
    related_alerts,
    status="Open"
):

    from datetime import datetime

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO incidents (
            title,
            severity,
            risk_score,
            related_alerts,
            status,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        title,
        severity,
        risk_score,
        related_alerts,
        status,
        current_time,
        current_time
    ))

    connection.commit()

    connection.close()

    # ============================================================
# GET INCIDENTS
# ============================================================

def get_incidents():

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            incident_id,
            title,
            severity,
            risk_score,
            related_alerts,
            status,
            created_at,
            updated_at
        FROM incidents
        ORDER BY incident_id DESC
    """)

    incidents = cursor.fetchall()

    connection.close()

    return incidents

# ============================================================
# CREATE INCIDENT FROM ALERT
# ============================================================

def create_incident_from_alert(alert):

    from datetime import datetime

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    title = (
        alert["type"]
        + " - "
        + alert["ip_address"]
    )

    cursor.execute("""
        INSERT INTO incidents (
            title,
            severity,
            risk_score,
            related_alerts,
            status,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        title,
        alert["severity"],
        alert["risk_score"],
        alert["alert_id"],
        "Open",
        current_time,
        current_time
    ))

    connection.commit()

    connection.close()

    # ============================================================
# CREATE INCIDENTS FROM ALERTS
# ============================================================

def create_incidents_from_alerts(alerts):

    from datetime import datetime

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    created_count = 0

    for alert in alerts:

        # Only create incidents for HIGH-risk alerts
        if alert["severity"] != "HIGH":
            continue

        title = (
            alert["type"]
            + " - "
            + alert["ip_address"]
        )

        cursor.execute("""
            SELECT incident_id
            FROM incidents
            WHERE title = ?
            AND related_alerts = ?
        """, (
            title,
            alert["alert_id"]
        ))

        existing_incident = cursor.fetchone()

        if existing_incident:
            continue

        cursor.execute("""
            INSERT INTO incidents (
                title,
                severity,
                risk_score,
                related_alerts,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            title,
            alert["severity"],
            alert["risk_score"],
            alert["alert_id"],
            "Open",
            current_time,
            current_time
        ))

        created_count += 1

    connection.commit()

    connection.close()

    return created_count

# ============================================================
# UPDATE INCIDENT STATUS
# ============================================================

def update_incident_status(incident_id, status):

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    from datetime import datetime

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        UPDATE incidents
        SET status = ?,
            updated_at = ?
        WHERE incident_id = ?
    """, (
        status,
        current_time,
        incident_id
    ))

    connection.commit()
    connection.close()

    # ============================================================
# CORRELATE ALERTS INTO INCIDENTS
# ============================================================

def correlate_alerts_into_incidents(alerts):

    from datetime import datetime

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    current_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # Group alerts by IP address
    alerts_by_ip = {}

    for alert in alerts:

        ip_address = alert["ip_address"]

        # Skip alerts containing multiple IP addresses
        if "," in ip_address:
            continue

        if ip_address not in alerts_by_ip:
            alerts_by_ip[ip_address] = []

        alerts_by_ip[ip_address].append(alert)

    created_count = 0

    for ip_address, ip_alerts in alerts_by_ip.items():

        if len(ip_alerts) < 2:
            continue

        alert_ids = sorted(
            set(
                alert["alert_id"]
                for alert in ip_alerts
            )
        )

        title = (
            "Correlated Security Incident - "
            + ip_address
        )

        maximum_risk = max(
            alert["risk_score"]
            for alert in ip_alerts
        )

        severity = "HIGH"

        related_alerts = ", ".join(
            alert_ids
        )

        cursor.execute("""
            SELECT incident_id
            FROM incidents
            WHERE title = ?
        """, (
            title,
        ))

        existing_incident = cursor.fetchone()

        if existing_incident:
            continue

        cursor.execute("""
            INSERT INTO incidents (
                title,
                severity,
                risk_score,
                related_alerts,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            title,
            severity,
            maximum_risk,
            related_alerts,
            "Open",
            current_time,
            current_time
        ))

        created_count += 1

    connection.commit()

    connection.close()

    return created_count

# ============================================================
# INCIDENT ANALYTICS
# ============================================================

def get_incident_statistics():

    connection = sqlite3.connect(DB_FILE)

    cursor = connection.cursor()

    statistics = {}

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
    """)

    statistics["total"] = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE severity = 'HIGH'
    """)

    statistics["high"] = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status = 'Open'
    """)

    statistics["open"] = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status = 'Investigating'
    """)

    statistics["investigating"] = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status = 'Resolved'
    """)

    statistics["resolved"] = cursor.fetchone()[0]

    cursor.execute("""
        SELECT AVG(risk_score)
        FROM incidents
    """)

    statistics["average_risk"] = (
        cursor.fetchone()[0] or 0
    )

    connection.close()

    return statistics