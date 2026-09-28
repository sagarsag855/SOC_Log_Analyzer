log_file = "data/security.log"

failed_logins = {}

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


print("\nSOCURITY ALERTS")
print("============================")

for ip_address, details in failed_logins.items():

    count = details["count"]

    if count >= 3:

        print("\nALERT ID: AUTH-001")
        print("TYPE: Brute-Force Attempt")
        print("SEVERITY: HIGH")
        print("USERNAME:", details["username"])
        print("IP ADDRESS:", ip_address)
        print("FAILED ATTEMPTS:", count)
        print("FIRST SEEN:", details["first_seen"])
        print("MESSAGE: Multiple failed login attempts detected.")