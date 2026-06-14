import win32evtlog
from collections import Counter

SERVER = "localhost"
LOG_TYPE = "Security"

handle = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)

event_counter = Counter()

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
        event_counter[event_id] += 1

print("\n===== TOP SECURITY EVENTS =====\n")

for event_id, count in event_counter.most_common(10):
    print(f"Event ID {event_id} : {count} occurrences")