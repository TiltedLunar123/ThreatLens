"""Generate synthetic Windows Security log data for testing ThreatLens."""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timedelta

# Common hostnames
HOSTS = [
    "DC-01", "DC-02", "WS-PC01", "WS-PC02", "WS-PC03",
    "SRV-FILE01", "SRV-WEB01", "SRV-DB01", "SRV-APP01", "WS-PC04",
]

# Common usernames
USERS = [
    "admin", "jdoe", "asmith", "bjones", "mwilson",
    "svc_deploy", "svc_monitor", "svc_backup", "operator1", "analyst2",
]

# Common IPs
INTERNAL_IPS = [
    "10.0.1.50", "10.0.1.51", "10.0.1.52", "10.0.1.100",
    "10.0.2.10", "10.0.2.20", "192.168.1.10", "192.168.1.20",
]

EXTERNAL_IPS = [
    "198.51.100.5", "203.0.113.42", "185.220.101.1",
    "45.33.32.156", "91.189.89.88",
]

PROCESSES = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE",
    "C:\\Windows\\System32\\lsass.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\System32\\taskhostw.exe",
]

RECON_TOOLS = [
    ("C:\\Windows\\System32\\whoami.exe", "whoami /priv"),
    ("C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all"),
    ("C:\\Windows\\System32\\systeminfo.exe", "systeminfo"),
    ("C:\\Windows\\System32\\net.exe", "net user /domain"),
    ("C:\\Windows\\System32\\nltest.exe", "nltest /dclist:domain.local"),
    ("C:\\Windows\\System32\\netstat.exe", "netstat -ano"),
]


def _make_event(ts: datetime, event_id: int, computer: str, **kwargs) -> dict:
    """Create a base event dict."""
    event = {
        "TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "EventID": event_id,
        "Computer": computer,
        "Source": kwargs.pop("source", "Security"),
        "EventData": {},
    }
    event["EventData"].update(kwargs)
    return event


def _gen_benign_logon(ts: datetime) -> dict:
    return _make_event(
        ts, 4624, random.choice(HOSTS),
        TargetUserName=random.choice(USERS),
        IpAddress=random.choice(INTERNAL_IPS),
        LogonType=random.choice([2, 3, 5, 7]),
        SubjectUserName="SYSTEM",
    )


def _gen_benign_process(ts: datetime) -> dict:
    proc = random.choice(PROCESSES)
    return _make_event(
        ts, 4688, random.choice(HOSTS),
        NewProcessName=proc,
        SubjectUserName=random.choice(USERS),
        CommandLine=proc,
        source="Sysmon",
    )


def _gen_benign_logoff(ts: datetime) -> dict:
    return _make_event(
        ts, 4634, random.choice(HOSTS),
        TargetUserName=random.choice(USERS),
    )


def _gen_benign_priv(ts: datetime) -> dict:
    return _make_event(
        ts, 4672, random.choice(HOSTS),
        SubjectUserName="SYSTEM",
        PrivilegeList="SeBackupPrivilege",
    )


BENIGN_GENERATORS = [
    _gen_benign_logon,
    _gen_benign_process,
    _gen_benign_logoff,
    _gen_benign_priv,
]


def gen_brute_force_chain(base_ts: datetime, attacker_ip: str, target_user: str) -> list[dict]:
    """Brute force -> successful logon -> priv esc -> recon -> lateral -> exfil."""
    events: list[dict] = []
    ts = base_ts

    # Phase 1: Brute force (8 failed logons)
    for i in range(8):
        ts += timedelta(seconds=random.randint(5, 30))
        events.append(_make_event(
            ts, 4625, "DC-01",
            TargetUserName=target_user,
            IpAddress=attacker_ip,
            LogonType=3,
            Status="0xC000006D",
        ))

    # Phase 2: Successful logon
    ts += timedelta(seconds=random.randint(10, 60))
    events.append(_make_event(
        ts, 4624, "DC-01",
        TargetUserName=target_user,
        IpAddress=attacker_ip,
        LogonType=3,
    ))

    # Phase 3: Privilege escalation
    ts += timedelta(seconds=random.randint(30, 120))
    events.append(_make_event(
        ts, 4672, "DC-01",
        SubjectUserName=target_user,
        PrivilegeList="SeDebugPrivilege\nSeTcbPrivilege",
    ))

    # Phase 4: Reconnaissance
    for tool, cmd in random.sample(RECON_TOOLS, 4):
        ts += timedelta(seconds=random.randint(3, 15))
        events.append(_make_event(
            ts, 1, "DC-01",
            NewProcessName=tool,
            CommandLine=cmd,
            SubjectUserName=target_user,
            source="Sysmon",
        ))

    # Phase 5: Lateral movement to other hosts
    lateral_hosts = random.sample(["SRV-FILE01", "SRV-WEB01", "SRV-DB01", "WS-PC02"], 3)
    for host in lateral_hosts:
        ts += timedelta(seconds=random.randint(30, 120))
        events.append(_make_event(
            ts, 4624, host,
            TargetUserName=target_user,
            IpAddress=attacker_ip,
            LogonType=3,
        ))

    # Phase 6: Suspicious process on target
    ts += timedelta(seconds=random.randint(60, 300))
    events.append(_make_event(
        ts, 1, lateral_hosts[0],
        NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        CommandLine="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        SubjectUserName=target_user,
        source="Sysmon",
    ))

    # Phase 7: Data staging / exfiltration
    ts += timedelta(seconds=random.randint(60, 300))
    events.append(_make_event(
        ts, 1, lateral_hosts[0],
        NewProcessName="C:\\Program Files\\7-Zip\\7z.exe",
        CommandLine="7z a C:\\temp\\data.7z C:\\Users\\*\\Documents",
        SubjectUserName=target_user,
        source="Sysmon",
    ))

    return events


def gen_credential_dump_chain(base_ts: datetime, attacker_user: str) -> list[dict]:
    """Credential dumping chain: SAM access + LSASS."""
    events: list[dict] = []
    ts = base_ts

    # SAM hive access
    ts += timedelta(seconds=random.randint(10, 60))
    events.append(_make_event(
        ts, 1, "DC-01",
        NewProcessName="C:\\Windows\\System32\\reg.exe",
        CommandLine="reg save HKLM\\SAM C:\\temp\\sam.hiv",
        SubjectUserName=attacker_user,
        source="Sysmon",
    ))

    # LSASS access
    ts += timedelta(seconds=random.randint(30, 120))
    events.append(_make_event(
        ts, 4663, "DC-01",
        SubjectUserName=attacker_user,
        ObjectName="\\REGISTRY\\MACHINE\\SAM",
    ))

    # Scheduled task for persistence
    ts += timedelta(seconds=random.randint(60, 300))
    events.append(_make_event(
        ts, 4698, "DC-01",
        SubjectUserName=attacker_user,
        TaskName="\\MaliciousTask",
    ))

    # Service creation
    ts += timedelta(seconds=random.randint(30, 120))
    events.append(_make_event(
        ts, 7045, "DC-01",
        SubjectUserName=attacker_user,
        ServiceName="UpdateSvc",
        ImagePath="C:\\Windows\\Temp\\payload.exe",
    ))

    return events


def gen_kerberos_chain(base_ts: datetime) -> list[dict]:
    """Kerberoasting chain."""
    events: list[dict] = []
    ts = base_ts

    # Multiple TGS requests with RC4
    for svc in ["sqlsvc", "websvc", "appsvc"]:
        ts += timedelta(seconds=random.randint(5, 30))
        events.append(_make_event(
            ts, 4769, "DC-01",
            TargetUserName=svc,
            TicketEncryptionType="0x17",
            IpAddress=random.choice(INTERNAL_IPS),
        ))

    return events


def gen_defense_evasion_chain(base_ts: datetime, user: str) -> list[dict]:
    """Defense evasion: log clearing + Defender disable."""
    events: list[dict] = []
    ts = base_ts

    ts += timedelta(seconds=random.randint(10, 60))
    events.append(_make_event(ts, 1102, "WS-PC03", SubjectUserName=user))

    ts += timedelta(seconds=random.randint(30, 120))
    events.append(_make_event(ts, 5001, "WS-PC03", SubjectUserName=user))

    ts += timedelta(seconds=random.randint(10, 60))
    events.append(_make_event(ts, 4719, "WS-PC03", SubjectUserName=user))

    return events


CHAIN_GENERATORS = [
    lambda ts: gen_brute_force_chain(ts, random.choice(EXTERNAL_IPS), random.choice(USERS[:5])),
    lambda ts: gen_credential_dump_chain(ts, random.choice(USERS[:5])),
    lambda ts: gen_kerberos_chain(ts),
    lambda ts: gen_defense_evasion_chain(ts, random.choice(USERS[:5])),
]


def generate(num_events: int = 1000, attack_chains: int = 3, noise_ratio: float = 0.9) -> list[dict]:
    """Generate a mix of benign noise + embedded attack sequences."""
    random.seed(42)
    events: list[dict] = []

    base_ts = datetime(2025, 6, 15, 6, 0, 0)

    # Calculate how many benign events
    num_benign = int(num_events * noise_ratio)

    # Generate benign events spread over 24 hours
    for _ in range(num_benign):
        ts = base_ts + timedelta(seconds=random.randint(0, 86400))
        gen = random.choice(BENIGN_GENERATORS)
        events.append(gen(ts))

    # Embed attack chains
    for i in range(attack_chains):
        chain_start = base_ts + timedelta(hours=random.randint(2, 20))
        gen = random.choice(CHAIN_GENERATORS)
        chain_events = gen(chain_start)
        events.extend(chain_events)

    # Sort by timestamp
    events.sort(key=lambda e: e["TimeCreated"])
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic log data for ThreatLens testing")
    parser.add_argument("--events", type=int, default=1000, help="Number of events to generate (default: 1000)")
    parser.add_argument("--attack-chains", type=int, default=3, help="Number of attack chains to embed (default: 3)")
    parser.add_argument("--noise-ratio", type=float, default=0.9, help="Ratio of benign events (default: 0.9)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output file path (default: stdout)")
    args = parser.parse_args()

    events = generate(
        num_events=args.events,
        attack_chains=args.attack_chains,
        noise_ratio=args.noise_ratio,
    )

    output = json.dumps(events, indent=2)

    if args.output:
        from pathlib import Path
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Generated {len(events)} events -> {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
