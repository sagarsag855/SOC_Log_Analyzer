log_file = "data/security.log"

failed_logins = {}
successful_logins = []

with open(log_file, "r") as file:
    logs = file.readlines()

for log in logs:
    log = log.strip()

    timestamp, event, username, ip_address = log.split(",")

    if event == "LOGIN_FAILED":

        if ip_address in failed_logins:
            failed_logins[ip_address]["count"] += 1
        else:
            failed_logins[ip_address] = {
                "count": 1,
                "username": username,
                "first_seen": timestamp
            }

    elif event == "LOGIN_SUCCESS":

        successful_logins.append({
            "timestamp": timestamp,
            "username": username,
            "ip_address": ip_address
        })


print("\nSECURITY ALERTS")
print("============================")

# Rule 1: Repeated failed logins

for ip_address, details in failed_logins.items():

    count = details["count"]

    if count >= 3:

        print("\n[AUTH-001]")
        print("Type: Repeated Failed Login")
        print("Severity: HIGH")
        print("Username:", details["username"])
        print("IP Address:", ip_address)
        print("Failed Attempts:", count)
        print("First Seen:", details["first_seen"])
        print("Message: Multiple failed login attempts detected.")


# Rule 2: Successful login after failed attempts

for login in successful_logins:

    ip_address = login["ip_address"]

    if ip_address in failed_logins:

        if failed_logins[ip_address]["count"] >= 3:

            print("\n[AUTH-002]")
            print("Type: Successful Login After Failed Attempts")
            print("Severity: MEDIUM")
            print("Username:", login["username"])
            print("IP Address:", ip_address)
            print("Login Time:", login["timestamp"])
            print("Message: Successful login occurred after multiple failed attempts.")