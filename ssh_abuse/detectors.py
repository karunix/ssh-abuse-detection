from collections import defaultdict
from datetime import timedelta

def detect_bruteforce(events, window_minutes=5, threshold=5):
    findings = []
    failures = defaultdict(list)

    for event in events:
        if event.success:
            continue
        failures[event.source_ip].append(event.timestamp)

    for ip, timestamps in failures.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            window = timestamps[i:i + threshold]
            if len(window) < threshold:
                continue

            if window[-1] - window[0] <= timedelta(minutes=window_minutes):
                findings.append({
                    "source_ip": ip,
                    "attempts": threshold,
                    "window_minutes": window_minutes
                })
                break

    return findings
