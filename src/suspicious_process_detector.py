import win32evtlog

SERVER = "localhost"
LOG_TYPE = "Security"

SUSPICIOUS_KEYWORDS = [
    "powershell",
    "cmd",
    "wscript",
    "cscript",
    "rundll32",
    "mshta",
    "certutil"
]

handle = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)

print("\n===== SUSPICIOUS PROCESS DETECTOR =====\n")

alerts = 0

while True:
    events = win32evtlog.ReadEventLog(
        handle,
        win32evtlog.EVENTLOG_BACKWARDS_READ |
        win32evtlog.EVENTLOG_SEQUENTIAL_READ,
        0
    )

    if not events:
        break

    for event in events:

        event_id = event.EventID & 0xFFFF

        if event_id == 4688:

            try:
                data = str(event.StringInserts)

                for keyword in SUSPICIOUS_KEYWORDS:

                    if keyword.lower() in data.lower():

                        print("\nALERT!")
                        print(f"Suspicious Process: {keyword}")

                        alerts += 1

            except:
                pass

    if alerts >= 20:
        break

print(f"\nTotal Alerts Generated: {alerts}")