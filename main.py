import argparse
from ssh_abuse.parser import parse_auth_log
from ssh_abuse.detectors import detect_bruteforce

def main():
    parser = argparse.ArgumentParser(
        description="Detect SSH brute-force attempts from auth logs"
    )

    parser.add_argument(
        "--log",
        default="samples/auth.log",
        help="Path to SSH auth log file"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Time window in minutes"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts threshold"
    )

    args = parser.parse_args()

    events = parse_auth_log(args.log)
    findings = detect_bruteforce(
        events,
        window_minutes=args.window,
        threshold=args.threshold
    )

    if not findings:
        print("No SSH abuse detected.")
        return

    for finding in findings:
        print(
            f"[!] Possible brute-force from {finding['source_ip']} "
            f"({finding['attempts']} attempts in "
            f"{finding['window_minutes']} minutes)"
        )

if __name__ == "__main__":
    main()
