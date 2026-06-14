import win32evtlog

SERVER = "localhost"
LOG_TYPE = "Security"

handle = win32evtlog.OpenEventLog(SERVER, LOG_TYPE)

print("\n===== PROCESS CREATION EVENTS =====\n")

found = 0

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
            print("Process Creation Event Found")
            found += 1

        if found >= 20:
            exit()