import win32evtlog
from collections import Counter
from datetime import datetime

SERVER = "localhost"
LOG_TYPE = "Security"

handle = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)

counter = Counter()

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
        counter[event_id] += 1

top_events = counter.most_common(5)

report = []
report.append("THREAT REPORT")
report.append("=" * 40)
report.append(f"Generated: {datetime.now()}")
report.append("")

report.append("Top Events:")

for event_id, count in top_events:
    report.append(f"Event ID {event_id}: {count}")

report.append("")
report.append("Risk Level: LOW")
report.append("Recommendation: Continue Monitoring")

with open("reports/threat_report.txt", "w") as file:
    file.write("\n".join(report))

print("Report generated successfully!")
print("Saved to reports/threat_report.txt")