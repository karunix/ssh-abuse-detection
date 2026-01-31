import re
from dateutil import parser as dtparser
from .models import SSHEvent

SSH_REGEX = re.compile(
    r'(?P<ts>\w+\s+\d+\s[\d:]+).*sshd.*(?P<status>Failed|Accepted).*for\s(?P<user>\S+)\sfrom\s(?P<ip>[\d.]+)'
)

def parse_auth_log(path):
    events = []

    with open(path, "r") as f:
        for line in f:
            match = SSH_REGEX.search(line)
            if not match:
                continue

            ts = dtparser.parse(match.group("ts"), fuzzy=True)
            success = match.group("status") == "Accepted"

            events.append(
                SSHEvent(
                    timestamp=ts,
                    user=match.group("user"),
                    source_ip=match.group("ip"),
                    success=success
                )
            )

    return events
