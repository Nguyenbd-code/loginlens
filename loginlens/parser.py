"""Parse sshd login lines from a Linux auth.log into AuthEvent records.

Supports classic syslog timestamps (no year) and ISO 8601 timestamps.
Anything that isn't a login attempt gets skipped.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

# Login outcomes.
SUCCESS = "success"
FAILURE = "failure"
INVALID_USER = "invalid_user"  # username doesn't exist on the server

# "Oct 19 04:01:02 host prog[pid]: message"
_CLASSIC_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

# "2026-10-19T04:01:02.123456-10:00 host prog[pid]: message"
_ISO_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

# usernames can be anything an attacker types, so match lazily up to " from "
_FAILED = re.compile(
    r"^Failed (?P<method>[\w-]+) for (?P<invalid>invalid user )?(?P<user>.*?) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>[\w-]+) for (?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)"
)
_INVALID = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?")

# rsyslog collapses duplicate lines into "message repeated N times: [ ... ]"
_REPEATED = re.compile(r"^message repeated (?P<count>\d+) times: \[ ?(?P<msg>.*?) ?\]$")


@dataclass(frozen=True)
class AuthEvent:
    """One SSH login attempt."""

    timestamp: datetime
    host: str
    outcome: str  # SUCCESS, FAILURE, or INVALID_USER
    user: str
    src_ip: str
    port: Optional[int]
    method: Optional[str]  # "password", "publickey", ... (None for "Invalid user" lines)
    invalid_user: bool  # True when the username doesn't exist on the server
    raw: str  # the original log line, kept for evidence

    @property
    def is_failure(self) -> bool:
        return self.outcome in (FAILURE, INVALID_USER)


def _parse_timestamp(m: re.Match, default_year: int) -> Optional[datetime]:
    if "ts" in m.groupdict() and m.group("ts"):
        ts = m.group("ts").replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            return None
    try:
        return datetime.strptime(
            f"{default_year} {m.group('month')} {m.group('day')} {m.group('time')}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_message(msg: str) -> Optional[dict]:
    m = _FAILED.match(msg)
    if m:
        invalid = bool(m.group("invalid"))
        return {
            "outcome": FAILURE,
            "user": m.group("user"),
            "src_ip": m.group("ip"),
            "port": int(m.group("port")),
            "method": m.group("method"),
            "invalid_user": invalid,
        }
    m = _ACCEPTED.match(msg)
    if m:
        return {
            "outcome": SUCCESS,
            "user": m.group("user"),
            "src_ip": m.group("ip"),
            "port": int(m.group("port")),
            "method": m.group("method"),
            "invalid_user": False,
        }
    m = _INVALID.match(msg)
    if m:
        return {
            "outcome": INVALID_USER,
            "user": m.group("user"),
            "src_ip": m.group("ip"),
            "port": int(m.group("port")) if m.group("port") else None,
            "method": None,
            "invalid_user": True,
        }
    return None


def parse_line(line: str, default_year: Optional[int] = None) -> list[AuthEvent]:
    """Parse one line. Returns a list since a "message repeated" line can be
    several attempts. default_year is used for syslog timestamps without a year.
    """
    line = line.rstrip("\r\n")
    year = default_year if default_year is not None else datetime.now().year
    prefix = _ISO_PREFIX.match(line) or _CLASSIC_PREFIX.match(line)
    if not prefix or not prefix.group("prog").endswith("sshd"):
        return []
    timestamp = _parse_timestamp(prefix, year)
    if timestamp is None:
        return []

    msg = prefix.group("msg")
    count = 1
    repeated = _REPEATED.match(msg)
    if repeated:
        count = int(repeated.group("count"))
        msg = repeated.group("msg")

    fields = _parse_message(msg)
    if not fields or not _valid_ip(fields["src_ip"]):
        return []
    event = AuthEvent(timestamp=timestamp, host=prefix.group("host"), raw=line, **fields)
    return [event] * count


def parse_lines(lines: Iterable[str], default_year: Optional[int] = None) -> Iterator[AuthEvent]:
    """Parse many lines, skipping anything that isn't an SSH login attempt."""
    for line in lines:
        yield from parse_line(line, default_year)


def parse_file(path: str, default_year: Optional[int] = None) -> list[AuthEvent]:
    """Read an auth.log file and return its login events in file order."""
    with open(path, encoding="utf-8", errors="replace") as f:
        return list(parse_lines(f, default_year))
