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


def detect_distributed_attack(events, window_minutes=5, ip_threshold=3):
    user_events = defaultdict(list)
    findings = []

    for event in events:
        if event.success:
            continue
        user_events[event.user].append((event.timestamp, event.source_ip))

    for user, entries in user_events.items():
        entries.sort()
        timestamps = [e[0] for e in entries]
        ips = [e[1] for e in entries]

        for i in range(len(entries)):
            window_end = timestamps[i] + timedelta(minutes=window_minutes)
            window_ips = set()

            for j in range(i, len(entries)):
                if timestamps[j] > window_end:
                    break
                window_ips.add(ips[j])

            if len(window_ips) >= ip_threshold:
                findings.append({
                    "user": user,
                    "unique_ips": len(window_ips),
                    "window_minutes": window_minutes
                })
                break

    return findings
