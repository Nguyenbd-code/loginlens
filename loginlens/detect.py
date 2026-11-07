"""Detection rules that turn parsed login events into alerts.

Three rules, each looking at activity from one source IP:
  - brute force: lots of failed passwords on one account in a short window
  - password spray: failures across many different accounts in a window
  - success after failures: a login that worked right after a run of
    failures from the same IP (most likely a compromised account)
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Hashable, Iterable, Optional

from .parser import FAILURE, SUCCESS, AuthEvent

BRUTE_FORCE = "brute_force"
PASSWORD_SPRAY = "password_spray"
SUCCESS_AFTER_FAILURES = "success_after_failures"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class DetectionConfig:
    brute_force_failures: int = 10
    brute_force_window: timedelta = timedelta(minutes=10)
    spray_users: int = 10
    spray_window: timedelta = timedelta(hours=1)
    saf_failures: int = 5
    saf_window: timedelta = timedelta(minutes=30)


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    src_ip: str
    users: tuple[str, ...]
    start: datetime
    end: datetime
    count: int  # failed attempts that triggered the alert
    summary: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "users": list(self.users),
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "count": self.count,
            "summary": self.summary,
        }


def _bursts(
    events: list[AuthEvent],
    window: timedelta,
    threshold: int,
    key: Optional[Callable[[AuthEvent], Hashable]] = None,
) -> list[list[AuthEvent]]:
    """Find runs of events where some `window`-long slice reaches `threshold`.

    Without `key` the threshold is on the number of events; with it, on the
    number of distinct keys (e.g. usernames). Overlapping hits get merged so
    one long attack gives one burst instead of dozens.
    """
    spans: list[list[int]] = []
    seen: Counter = Counter()
    left = 0
    for right, ev in enumerate(events):
        seen[key(ev) if key else right] += 1
        while ev.timestamp - events[left].timestamp > window:
            k = key(events[left]) if key else left
            seen[k] -= 1
            if not seen[k]:
                del seen[k]
            left += 1
        if len(seen) >= threshold:
            if spans and left <= spans[-1][1]:
                spans[-1][1] = right
            else:
                spans.append([left, right])
    return [events[a : b + 1] for a, b in spans]


def _by_ip(events: Iterable[AuthEvent], keep: Callable[[AuthEvent], bool]) -> dict[str, list[AuthEvent]]:
    groups: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if keep(e):
            groups[e.src_ip].append(e)
    for evs in groups.values():
        evs.sort(key=lambda e: e.timestamp)
    return groups


def detect_brute_force(events: list[AuthEvent], cfg: DetectionConfig = DetectionConfig()) -> list[Alert]:
    # only "Failed password" lines, since an invalid user guess also logs an
    # "Invalid user" line and would get counted twice
    per_target: dict[tuple[str, str], list[AuthEvent]] = defaultdict(list)
    for ip, evs in _by_ip(events, lambda e: e.outcome == FAILURE).items():
        for e in evs:
            per_target[(ip, e.user)].append(e)

    alerts = []
    for (ip, user), evs in per_target.items():
        for burst in _bursts(evs, cfg.brute_force_window, cfg.brute_force_failures):
            minutes = (burst[-1].timestamp - burst[0].timestamp).total_seconds() / 60
            alerts.append(Alert(
                BRUTE_FORCE, "medium", ip, (user,), burst[0].timestamp, burst[-1].timestamp, len(burst),
                f"{len(burst)} failed passwords for '{user}' in {minutes:.0f} min",
            ))
    return alerts


def detect_password_spray(events: list[AuthEvent], cfg: DetectionConfig = DetectionConfig()) -> list[Alert]:
    alerts = []
    for ip, evs in _by_ip(events, lambda e: e.is_failure).items():
        for burst in _bursts(evs, cfg.spray_window, cfg.spray_users, key=lambda e: e.user):
            users = tuple(sorted({e.user for e in burst}))
            attempts = sum(1 for e in burst if e.outcome == FAILURE) or len(burst)
            minutes = (burst[-1].timestamp - burst[0].timestamp).total_seconds() / 60
            alerts.append(Alert(
                PASSWORD_SPRAY, "high", ip, users, burst[0].timestamp, burst[-1].timestamp, attempts,
                f"{len(users)} different accounts tried in {minutes:.0f} min",
            ))
    return alerts


def detect_success_after_failures(events: list[AuthEvent], cfg: DetectionConfig = DetectionConfig()) -> list[Alert]:
    alerts = []
    for ip, evs in _by_ip(events, lambda e: e.outcome in (FAILURE, SUCCESS)).items():
        recent: deque[AuthEvent] = deque()
        for e in evs:
            while recent and e.timestamp - recent[0].timestamp > cfg.saf_window:
                recent.popleft()
            if e.outcome == FAILURE:
                recent.append(e)
            elif len(recent) >= cfg.saf_failures:
                users = tuple(sorted({f.user for f in recent} | {e.user}))
                alerts.append(Alert(
                    SUCCESS_AFTER_FAILURES, "critical", ip, users, recent[0].timestamp, e.timestamp, len(recent),
                    f"'{e.user}' logged in after {len(recent)} failed attempts from this IP",
                ))
                recent.clear()
    return alerts


def detect(events: list[AuthEvent], cfg: DetectionConfig = DetectionConfig()) -> list[Alert]:
    """Run every rule. Alerts come back most severe first, then by time."""
    alerts = (
        detect_brute_force(events, cfg)
        + detect_password_spray(events, cfg)
        + detect_success_after_failures(events, cfg)
    )
    return sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], a.start))
