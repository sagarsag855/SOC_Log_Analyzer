from src.detector import detect_threats, generate_summary
from src.database import (
    initialize_database,
    save_alert,
    get_alerts
)

LOG_FILE = "data/security.log"


# ==========================================
# READ SECURITY LOGS
# ==========================================

with open(LOG_FILE, "r") as file:
    logs = file.readlines()


# ==========================================
# DETECT SECURITY THREATS
# ==========================================

alerts = detect_threats(logs)


# ==========================================
# GENERATE SOC SUMMARY
# ==========================================

summary = generate_summary(alerts)


# ==========================================
# INITIALIZE DATABASE
# ==========================================

initialize_database()


# ==========================================
# SAVE ALERTS
# ==========================================

for alert in alerts:
    save_alert(alert)


# ==========================================
# PRINT SOC SUMMARY
# ==========================================

print("\nSOC SUMMARY")
print("============================")
print("Total Alerts:", summary["total_alerts"])
print("High Risk:", summary["high_risk"])
print("Medium Risk:", summary["medium_risk"])
print("Average Risk Score:", round(summary["average_score"], 2))


# ==========================================
# PRINT DETECTED SECURITY ALERTS
# ==========================================

print("\nSECURITY ALERTS")
print("============================")

for alert in alerts:
    print("\nAlert ID:", alert["alert_id"])
    print("Type:", alert["type"])
    print("Severity:", alert["severity"])
    print("Risk Score:", alert["risk_score"])
    print("Username:", alert["username"])
    print("IP Address:", alert["ip_address"])
    print("Attempts / Users:", alert["count"])
    print("First Seen:", alert["first_seen"])
    print("Last Seen:", alert["last_seen"])
    print("Message:", alert["message"])


# ==========================================
# READ STORED DATABASE ALERTS
# ==========================================

stored_alerts = get_alerts()


# ==========================================
# PRINT DATABASE ALERTS
# ==========================================

print("\nSTORED DATABASE ALERTS")
print("============================")

for alert in stored_alerts:

    print("\nAlert ID:", alert[0])
    print("Type:", alert[1])
    print("Severity:", alert[2])
    print("Risk Score:", alert[3])
    print("Username:", alert[4])
    print("IP Address:", alert[5])
    print("Attempts / Users:", alert[6])
    print("First Seen:", alert[7])
    print("Last Seen:", alert[8])
    print("Message:", alert[9])
    print("Status:", alert[10])