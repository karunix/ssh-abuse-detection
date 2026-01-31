from dataclasses import dataclass
from datetime import datetime

@dataclass
class SSHEvent:
    timestamp: datetime
    user: str
    source_ip: str
    success: bool
