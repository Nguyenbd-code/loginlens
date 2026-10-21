"""Generate fake SSH auth logs with known attacks planted in them.

Real logs have real usernames and IPs, so the repo uses generated data.
The planted attacks double as ground truth for testing detection.
All public IPs are from the RFC 5737 documentation ranges.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

BRUTE_FORCE = "brute_force"  # one IP hammering one account
PASSWORD_SPRAY = "password_spray"  # one IP trying a few passwords across many accounts
SUCCESS_AFTER_FAILURES = "success_after_failures"  # many failures, then a login that worked

STAFF = ["brandon", "alice", "kai", "leilani", "noa"]
OFFICE_IPS = ["10.0.0.11", "10.0.0.12", "10.0.0.13", "192.168.1.20", "192.168.1.21"]
DEPLOY_IP = "10.0.0.50"
BACKUP_IP = "10.0.0.60"

# usernames commonly seen in spraying/scanning
COMMON_USERNAMES = [
    "admin", "test", "user", "oracle", "postgres", "ubuntu", "git", "ftp",
    "guest", "pi", "support", "mysql", "jenkins", "dev", "demo", "operator",
    "hadoop", "nagios", "temp", "student", "server", "web",
]


@dataclass
class PlantedAttack:
    """Ground truth for one planted attack."""

    kind: str
    src_ip: str
    users: list[str]
    start: datetime
    end: datetime
    attempts: int  # password attempts made by the attacker
    compromised_user: Optional[str] = None  # set when the attacker got in

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "src_ip": self.src_ip,
            "users": sorted(self.users),
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "attempts": self.attempts,
            "compromised_user": self.compromised_user,
        }


@dataclass
class GeneratedLog:
    lines: list[str]
    attacks: list[PlantedAttack] = field(default_factory=list)

    def truth_json(self) -> str:
        return json.dumps([a.to_dict() for a in self.attacks], indent=2) + "\n"


class _LogWriter:
    """Collects sshd messages, outputs them as sorted syslog lines."""

    def __init__(self, host: str, rng: random.Random):
        self.host = host
        self.rng = rng
        self._entries: list[tuple[datetime, int, str]] = []
        self._pid = rng.randint(1000, 5000)

    def _new_connection(self) -> tuple[int, int]:
        self._pid += self.rng.randint(1, 40)
        return self._pid, self.rng.randint(32768, 60999)

    def emit(self, ts: datetime, pid: int, message: str) -> None:
        self._entries.append((ts, len(self._entries), f"sshd[{pid}]: {message}"))

    def failed_login(self, ts: datetime, user: str, ip: str, user_exists: bool, tries: int = 1) -> datetime:
        """One connection with `tries` bad passwords. Returns the end time."""
        pid, port = self._new_connection()
        t = ts
        if not user_exists:
            self.emit(t, pid, f"Invalid user {user} from {ip} port {port}")
            t += timedelta(seconds=self.rng.randint(1, 2))
        who = user if user_exists else f"invalid user {user}"
        self.emit(t, pid, f"Failed password for {who} from {ip} port {port} ssh2")
        if tries > 1:
            # rsyslog collapses the duplicates
            t += timedelta(seconds=self.rng.randint(2, 6))
            self.emit(
                t, pid,
                f"message repeated {tries - 1} times: [ Failed password for {who} from {ip} port {port} ssh2]",
            )
        t += timedelta(seconds=1)
        closed_who = f"authenticating user {user}" if user_exists else f"invalid user {user}"
        self.emit(t, pid, f"Connection closed by {closed_who} {ip} port {port} [preauth]")
        return t

    def accepted_login(self, ts: datetime, user: str, ip: str, method: str, uid: int, minutes: int) -> None:
        pid, port = self._new_connection()
        if method == "publickey":
            fp = "".join(self.rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for _ in range(43))
            self.emit(ts, pid, f"Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:{fp}")
        else:
            self.emit(ts, pid, f"Accepted password for {user} from {ip} port {port} ssh2")
        self.emit(ts, pid, f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)")
        end = ts + timedelta(minutes=minutes, seconds=self.rng.randint(0, 59))
        self.emit(end, pid, f"Received disconnect from {ip} port {port}:11: disconnected by user")
        self.emit(end, pid, f"pam_unix(sshd:session): session closed for user {user}")

    def lines(self) -> list[str]:
        out = []
        for ts, _, rest in sorted(self._entries):
            out.append(f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {self.host} {rest}")
        return out


def _at(day: datetime, rng: random.Random, first_hour: int, last_hour: int) -> datetime:
    return day + timedelta(
        hours=rng.randint(first_hour, last_hour),
        minutes=rng.randint(0, 59),
        seconds=rng.randint(0, 59),
    )


def _normal_activity(log: _LogWriter, rng: random.Random, day: datetime) -> None:
    uids = {name: 1000 + i for i, name in enumerate(STAFF)}
    home_ip = {name: OFFICE_IPS[i % len(OFFICE_IPS)] for i, name in enumerate(STAFF)}

    # staff logins during the workday, sometimes after a typo
    for user in STAFF:
        for _ in range(rng.randint(1, 4)):
            ts = _at(day, rng, 7, 17)
            method = "publickey" if rng.random() < 0.6 else "password"
            if method == "password" and rng.random() < 0.15:
                ended = log.failed_login(ts, user, home_ip[user], user_exists=True)
                ts = ended + timedelta(seconds=rng.randint(4, 15))
            log.accepted_login(ts, user, home_ip[user], method, uids[user], minutes=rng.randint(5, 120))

    # deploy bot every 2 hours + nightly backup
    for hour in range(0, 24, 2):
        ts = day + timedelta(hours=hour, minutes=5, seconds=rng.randint(0, 20))
        log.accepted_login(ts, "deploy", DEPLOY_IP, "publickey", 1100, minutes=1)
    log.accepted_login(day + timedelta(hours=2, minutes=30), "backup", BACKUP_IP, "publickey", 1101, minutes=18)

    # scanner noise (1-2 tries and gone), shouldn't trigger anything
    for host_part in rng.sample(range(2, 250), 10):
        ip = f"192.0.2.{host_part}"
        ts = _at(day, rng, 0, 23)
        for _ in range(rng.randint(1, 2)):
            user = rng.choice(["root", "admin", "test", "ubuntu"])
            ts = log.failed_login(ts, user, ip, user_exists=(user == "root")) + timedelta(minutes=rng.randint(3, 40))


def _plant_brute_force(log: _LogWriter, rng: random.Random, day: datetime) -> PlantedAttack:
    ip = f"203.0.113.{rng.randint(10, 99)}"
    start = ts = _at(day, rng, 1, 4)
    attempts = 0
    for _ in range(20):  # 20 connections, 3 guesses each
        ts = log.failed_login(ts, "root", ip, user_exists=True, tries=3)
        attempts += 3
        ts += timedelta(seconds=rng.randint(2, 6))
    return PlantedAttack(BRUTE_FORCE, ip, ["root"], start, ts, attempts)


def _plant_password_spray(log: _LogWriter, rng: random.Random, day: datetime) -> PlantedAttack:
    ip = f"198.51.100.{rng.randint(10, 99)}"
    targets = rng.sample(COMMON_USERNAMES, 20) + rng.sample(STAFF, 3)
    rng.shuffle(targets)
    start = ts = _at(day, rng, 10, 15)
    for user in targets:
        ts = log.failed_login(ts, user, ip, user_exists=user in STAFF)
        ts += timedelta(seconds=rng.randint(30, 90))  # slow to stay under lockout limits
    return PlantedAttack(PASSWORD_SPRAY, ip, targets, start, ts, len(targets))


def _plant_success_after_failures(log: _LogWriter, rng: random.Random, day: datetime) -> PlantedAttack:
    ip = f"203.0.113.{rng.randint(100, 199)}"
    victim = rng.choice(STAFF)
    start = ts = _at(day, rng, 19, 22)
    attempts = 0
    for _ in range(12):  # 12 connections, 3 guesses each
        ts = log.failed_login(ts, victim, ip, user_exists=True, tries=3)
        attempts += 3
        ts += timedelta(seconds=rng.randint(3, 10))
    log.accepted_login(ts, victim, ip, "password", 1000 + STAFF.index(victim), minutes=rng.randint(3, 12))
    attempts += 1
    return PlantedAttack(SUCCESS_AFTER_FAILURES, ip, [victim], start, ts, attempts, compromised_user=victim)


def generate(seed: int = 42, start: datetime = datetime(2026, 10, 12), days: int = 1, host: str = "web01") -> GeneratedLog:
    """Generate `days` days of traffic with one of each attack planted."""
    if days < 1:
        raise ValueError("days must be at least 1")
    rng = random.Random(seed)
    log = _LogWriter(host, rng)
    day_starts = [start + timedelta(days=d) for d in range(days)]
    for day in day_starts:
        _normal_activity(log, rng, day)

    attacks = [
        _plant_brute_force(log, rng, rng.choice(day_starts)),
        _plant_password_spray(log, rng, rng.choice(day_starts)),
        _plant_success_after_failures(log, rng, rng.choice(day_starts)),
    ]
    attacks.sort(key=lambda a: a.start)
    return GeneratedLog(lines=log.lines(), attacks=attacks)
