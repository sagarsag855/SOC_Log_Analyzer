from datetime import datetime, timedelta


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(severity):

    if severity == "HIGH":
        return 80

    elif severity == "MEDIUM":
        return 50

    else:
        return 20


# ============================================================
# TIMESTAMP PARSER
# ============================================================

def parse_timestamp(timestamp):

    return datetime.strptime(
        timestamp,
        "%Y-%m-%d %H:%M:%S"
    )


# ============================================================
# THREAT DETECTION
# ============================================================

def detect_threats(logs):

    failed_logins = {}

    successful_logins = []

    ip_users = {}

    alerts = []


    # ========================================================
    # READ AND NORMALIZE LOGS
    # ========================================================

    for log in logs:

        log = log.strip()

        if not log:
            continue

        try:

            timestamp, event, username, ip_address = (
                log.split(",")
            )

        except ValueError:

            continue

        event_time = parse_timestamp(timestamp)


        # ----------------------------------------------------
        # TRACK USERNAMES PER IP
        # ----------------------------------------------------

        if ip_address not in ip_users:

            ip_users[ip_address] = set()

        ip_users[ip_address].add(username)


        # ----------------------------------------------------
        # TRACK FAILED LOGINS
        # ----------------------------------------------------

        if event == "LOGIN_FAILED":

            if ip_address not in failed_logins:

                failed_logins[ip_address] = []

            failed_logins[ip_address].append({

                "timestamp": event_time,

                "username": username

            })


        # ----------------------------------------------------
        # TRACK SUCCESSFUL LOGINS
        # ----------------------------------------------------

        elif event == "LOGIN_SUCCESS":

            successful_logins.append({

                "timestamp": event_time,

                "username": username,

                "ip_address": ip_address

            })


    # ========================================================
    # AUTH-001
    # REPEATED FAILED LOGIN
    # ========================================================

    for ip_address, attempts in failed_logins.items():

        attempts.sort(
            key=lambda x: x["timestamp"]
        )

        for i in range(len(attempts)):

            window_start = attempts[i]["timestamp"]

            window_end = (
                window_start
                + timedelta(minutes=5)
            )

            window_attempts = [

                attempt

                for attempt in attempts

                if window_start
                <= attempt["timestamp"]
                <= window_end

            ]

            if len(window_attempts) >= 3:

                usernames = sorted(
                    set(
                        attempt["username"]
                        for attempt in window_attempts
                    )
                )

                alerts.append({

                    "alert_id":
                        "AUTH-001",

                    "type":
                        "Repeated Failed Login",

                    "severity":
                        "HIGH",

                    "risk_score":
                        80,

                    "username":
                        ", ".join(usernames),

                    "ip_address":
                        ip_address,

                    "count":
                        len(window_attempts),

                    "first_seen":
                        window_attempts[0]["timestamp"].strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                    "last_seen":
                        window_attempts[-1]["timestamp"].strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                    "message":
                        "Three or more failed login attempts "
                        "were detected from the same IP within "
                        "a five-minute window."

                })

                break


    # ========================================================
    # AUTH-002
    # SUCCESSFUL LOGIN AFTER FAILED ATTEMPTS
    # ========================================================

    for login in successful_logins:

        ip_address = login["ip_address"]

        if ip_address not in failed_logins:

            continue

        recent_failures = [

            attempt

            for attempt in failed_logins[ip_address]

            if timedelta(0)
            <= (
                login["timestamp"]
                - attempt["timestamp"]
            )
            <= timedelta(minutes=5)

        ]

        if len(recent_failures) >= 3:

            alerts.append({

                "alert_id":
                    "AUTH-002",

                "type":
                    "Successful Login After Failed Attempts",

                "severity":
                    "MEDIUM",

                "risk_score":
                    50,

                "username":
                    login["username"],

                "ip_address":
                    ip_address,

                "count":
                    len(recent_failures),

                "first_seen":
                    recent_failures[0]["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),

                "last_seen":
                    login["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),

                "message":
                    "A successful login occurred after "
                    "multiple failed login attempts within "
                    "five minutes."

            })


    # ========================================================
    # AUTH-003
    # MULTIPLE USERNAMES FROM ONE IP
    # ========================================================

    for ip_address, usernames in ip_users.items():

        if len(usernames) >= 3:

            alerts.append({

                "alert_id":
                    "AUTH-003",

                "type":
                    "Multiple Usernames from One IP",

                "severity":
                    "MEDIUM",

                "risk_score":
                    50,

                "username":
                    ", ".join(sorted(usernames)),

                "ip_address":
                    ip_address,

                "count":
                    len(usernames),

                "first_seen":
                    "",

                "last_seen":
                    "",

                "message":
                    "Multiple usernames were observed "
                    "from the same IP address."

            })


    # ========================================================
    # AUTH-004
    # RAPID BRUTE-FORCE ACTIVITY
    # ========================================================

    for ip_address, attempts in failed_logins.items():

        attempts.sort(
            key=lambda x: x["timestamp"]
        )

        for i in range(len(attempts)):

            window_start = attempts[i]["timestamp"]

            window_end = (
                window_start
                + timedelta(minutes=2)
            )

            rapid_attempts = [

                attempt

                for attempt in attempts

                if window_start
                <= attempt["timestamp"]
                <= window_end

            ]

            if len(rapid_attempts) >= 5:

                usernames = sorted(
                    set(
                        attempt["username"]
                        for attempt in rapid_attempts
                    )
                )

                alerts.append({

                    "alert_id":
                        "AUTH-004",

                    "type":
                        "Rapid Brute-Force Activity",

                    "severity":
                        "HIGH",

                    "risk_score":
                        90,

                    "username":
                        ", ".join(usernames),

                    "ip_address":
                        ip_address,

                    "count":
                        len(rapid_attempts),

                    "first_seen":
                        rapid_attempts[0]["timestamp"].strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                    "last_seen":
                        rapid_attempts[-1]["timestamp"].strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                    "message":
                        "Five or more failed authentication "
                        "attempts were detected from the same "
                        "IP within a two-minute window."

                })

                break


    # ========================================================
    # AUTH-005
    # UNUSUAL LOGIN TIME
    # ========================================================

    for login in successful_logins:

        login_hour = login["timestamp"].hour

        if login_hour < 6 or login_hour >= 23:

            alerts.append({

                "alert_id":
                    "AUTH-005",

                "type":
                    "Unusual Login Time",

                "severity":
                    "MEDIUM",

                "risk_score":
                    50,

                "username":
                    login["username"],

                "ip_address":
                    login["ip_address"],

                "count":
                    1,

                "first_seen":
                    login["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),

                "last_seen":
                    login["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),

                "message":
                    "A successful login was detected "
                    "outside the configured normal "
                    "login hours."

            })


    # ========================================================
    # AUTH-006
    # SAME USER FROM MULTIPLE IP ADDRESSES
    # ========================================================

    user_ips = {}

    for login in successful_logins:

        username = login["username"]

        ip_address = login["ip_address"]

        if username not in user_ips:

            user_ips[username] = set()

        user_ips[username].add(ip_address)


    for username, ip_addresses in user_ips.items():

        if len(ip_addresses) >= 2:

            alerts.append({

                "alert_id":
                    "AUTH-006",

                "type":
                    "Same User from Multiple IPs",

                "severity":
                    "MEDIUM",

                "risk_score":
                    50,

                "username":
                    username,

                "ip_address":
                    ", ".join(
                        sorted(ip_addresses)
                    ),

                "count":
                    len(ip_addresses),

                "first_seen":
                    "",

                "last_seen":
                    "",

                "message":
                    "The same username was observed "
                    "logging in successfully from multiple "
                    "IP addresses."

            })


    # ========================================================
    # AUTH-007
    # LOGIN AFTER LONG INACTIVITY
    # ========================================================

    user_logins = {}

    for login in successful_logins:

        username = login["username"]

        if username not in user_logins:

            user_logins[username] = []

        user_logins[username].append(login)


    for username, logins in user_logins.items():

        logins.sort(
            key=lambda x: x["timestamp"]
        )

        for i in range(1, len(logins)):

            previous_login = logins[i - 1]

            current_login = logins[i]

            inactive_period = (
                current_login["timestamp"]
                - previous_login["timestamp"]
            )

            if inactive_period >= timedelta(hours=8):

                alerts.append({

                    "alert_id":
                        "AUTH-007",

                    "type":
                        "Login After Long Inactivity",

                    "severity":
                        "MEDIUM",

                    "risk_score":
                        50,

                    "username":
                        username,

                    "ip_address":
                        current_login["ip_address"],

                    "count":
                        1,

                    "first_seen":
                        previous_login["timestamp"].strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                    "last_seen":
                        current_login["timestamp"].strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),

                    "message":
                        "A successful login occurred after "
                        "a long period of inactivity for "
                        "the same username."

                })

                break


    # ========================================================
    # REMOVE DUPLICATE ALERTS
    # ========================================================

    unique_alerts = []

    seen = set()


    for alert in alerts:

        fingerprint = (

            alert["alert_id"],

            alert["ip_address"],

            alert["username"]

        )

        if fingerprint not in seen:

            seen.add(fingerprint)

            unique_alerts.append(alert)


    # ========================================================
    # CORR-001
    # MULTIPLE ALERTS FROM SAME IP
    # ========================================================

    ip_alerts = {}


    for alert in unique_alerts:

        ip_address = alert["ip_address"]

        if ip_address not in ip_alerts:

            ip_alerts[ip_address] = []

        ip_alerts[ip_address].append(alert)


    correlation_alerts = []


    for ip_address, ip_alert_list in ip_alerts.items():

        alert_types = sorted(
            set(
                alert["alert_id"]
                for alert in ip_alert_list
            )
        )


        if len(alert_types) >= 2:

            correlation_alerts.append({

                "alert_id":
                    "CORR-001",

                "type":
                    "Multiple Security Alerts from Same IP",

                "severity":
                    "HIGH",

                "risk_score":
                    90,

                "username":
                    ", ".join(
                        sorted(
                            set(
                                alert["username"]
                                for alert in ip_alert_list
                            )
                        )
                    ),

                "ip_address":
                    ip_address,

                "count":
                    len(alert_types),

                "first_seen":
                    "",

                "last_seen":
                    "",

                "message":
                    "Multiple different security detection "
                    "rules were triggered by the same IP address."

            })


    unique_alerts.extend(
        correlation_alerts
    )

    # ========================================================
    # CORR-002
    # MULTIPLE HIGH-RISK ALERTS FROM SAME IP
    # ========================================================

    high_risk_by_ip = {}

    for alert in unique_alerts:

        if alert["severity"] != "HIGH":
            continue

        ip_address = alert["ip_address"]

        if ip_address not in high_risk_by_ip:

            high_risk_by_ip[ip_address] = []

        high_risk_by_ip[ip_address].append(alert)


    for ip_address, high_alerts in high_risk_by_ip.items():

        if len(high_alerts) >= 2:

            usernames = sorted(
                set(
                    alert["username"]
                    for alert in high_alerts
                )
            )

            unique_alerts.append({

                "alert_id":
                    "CORR-002",

                "type":
                    "Multiple High-Risk Alerts from Same IP",

                "severity":
                    "HIGH",

                "risk_score":
                    100,

                "username":
                    ", ".join(usernames),

                "ip_address":
                    ip_address,

                "count":
                    len(high_alerts),

                "first_seen":
                    "",

                "last_seen":
                    "",

                "message":
                    "Multiple high-risk security alerts "
                    "were detected from the same IP address."
            })
            
    return unique_alerts


# ============================================================
# SOC SUMMARY
# ============================================================

def generate_summary(alerts):

    total_alerts = len(alerts)

    high_risk = 0

    medium_risk = 0

    total_score = 0


    for alert in alerts:

        if alert["severity"] == "HIGH":

            high_risk += 1

        elif alert["severity"] == "MEDIUM":

            medium_risk += 1

        total_score += alert["risk_score"]


    if total_alerts > 0:

        average_score = (
            total_score / total_alerts
        )

    else:

        average_score = 0


    return {

        "total_alerts":
            total_alerts,

        "high_risk":
            high_risk,

        "medium_risk":
            medium_risk,

        "average_score":
            average_score

    }