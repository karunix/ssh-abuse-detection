from ssh_abuse.parser import parse_auth_log
from ssh_abuse.detectors import detect_bruteforce

def main():
    events = parse_auth_log("samples/auth.log")
    findings = detect_bruteforce(events)

    for finding in findings:
        print(
            f"[!] Possible brute-force from {finding['source_ip']} "
            f"({finding['attempts']} attempts in "
            f"{finding['window_minutes']} minutes)"
        )

if __name__ == "__main__":
    main()
