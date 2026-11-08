from datetime import datetime, timedelta

import pytest

from loginlens.detect import (
    BRUTE_FORCE,
    PASSWORD_SPRAY,
    SUCCESS_AFTER_FAILURES,
    DetectionConfig,
    detect,
    detect_brute_force,
    detect_password_spray,
    detect_success_after_failures,
)
from loginlens.generate import generate
from loginlens.parser import FAILURE, INVALID_USER, SUCCESS, AuthEvent, parse_lines

T0 = datetime(2026, 10, 12, 3, 0, 0)


def ev(seconds, outcome, user="root", ip="203.0.113.5"):
    return AuthEvent(
        timestamp=T0 + timedelta(seconds=seconds),
        host="web01",
        outcome=outcome,
        user=user,
        src_ip=ip,
        port=40000,
        method=None if outcome == INVALID_USER else "password",
        invalid_user=outcome == INVALID_USER,
        raw="",
    )


def fails(n, every=10, **kw):
    return [ev(i * every, FAILURE, **kw) for i in range(n)]


# brute force

def test_brute_force_at_threshold():
    alerts = detect_brute_force(fails(10))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule == BRUTE_FORCE and a.users == ("root",) and a.count == 10


def test_brute_force_below_threshold():
    assert detect_brute_force(fails(9)) == []


def test_brute_force_too_slow_to_count():
    # 10 failures, but an hour apart each: nothing in any 10 minute window
    assert detect_brute_force(fails(10, every=3600)) == []


def test_one_long_attack_is_one_alert():
    alerts = detect_brute_force(fails(200, every=5))
    assert len(alerts) == 1
    assert alerts[0].count == 200


def test_two_separate_attacks_are_two_alerts():
    first = fails(12)
    second = [ev(7200 + i * 10, FAILURE) for i in range(12)]
    assert len(detect_brute_force(first + second)) == 2


def test_brute_force_is_per_account():
    # 5 failures on each of 3 accounts is not brute forcing any of them
    events = fails(5, user="root") + fails(5, user="admin") + fails(5, user="oracle")
    assert detect_brute_force(events) == []


def test_brute_force_ignores_invalid_user_lines():
    # each bad guess on a nonexistent user logs 2 lines; only count one
    events = []
    for i in range(6):
        events += [ev(i * 10, INVALID_USER, user="ghost"), ev(i * 10 + 1, FAILURE, user="ghost")]
    assert detect_brute_force(events) == []


# password spray

def test_spray_detected():
    users = [f"user{i}" for i in range(12)]
    events = [ev(i * 60, FAILURE, user=u) for i, u in enumerate(users)]
    alerts = detect_password_spray(events)
    assert len(alerts) == 1
    assert alerts[0].rule == PASSWORD_SPRAY
    assert set(alerts[0].users) == set(users)


def test_spray_counts_invalid_user_only_lines():
    # some sshd setups only log "Invalid user" for accounts that don't exist
    events = [ev(i * 60, INVALID_USER, user=f"u{i}") for i in range(10)]
    alerts = detect_password_spray(events)
    assert len(alerts) == 1
    assert alerts[0].count == 10


def test_spray_needs_enough_accounts():
    events = [ev(i * 60, FAILURE, user=f"user{i % 9}") for i in range(30)]
    assert detect_password_spray(events) == []


def test_spray_spread_over_a_day_is_not_flagged():
    events = [ev(i * 7200, FAILURE, user=f"user{i}") for i in range(12)]
    assert detect_password_spray(events) == []


# success after failures

def test_success_after_failures():
    events = fails(6) + [ev(70, SUCCESS)]
    alerts = detect_success_after_failures(events)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule == SUCCESS_AFTER_FAILURES and a.severity == "critical"
    assert a.count == 6 and a.end == T0 + timedelta(seconds=70)


def test_typo_then_login_is_fine():
    events = [ev(0, FAILURE, user="alice", ip="10.0.0.11"), ev(8, SUCCESS, user="alice", ip="10.0.0.11")]
    assert detect(events) == []


def test_old_failures_dont_count():
    events = fails(6) + [ev(3 * 3600, SUCCESS)]
    assert detect_success_after_failures(events) == []


def test_success_from_a_different_ip_is_not_linked():
    events = fails(6, ip="203.0.113.5") + [ev(70, SUCCESS, ip="10.0.0.11")]
    assert detect_success_after_failures(events) == []


def test_spray_then_success_on_another_account():
    events = [ev(i * 30, FAILURE, user=f"user{i}") for i in range(6)] + [ev(200, SUCCESS, user="kai")]
    alerts = detect_success_after_failures(events)
    assert len(alerts) == 1
    assert "kai" in alerts[0].users


# config and ordering

def test_thresholds_are_configurable():
    strict = DetectionConfig(brute_force_failures=3)
    assert detect_brute_force(fails(3), strict)
    assert detect_brute_force(fails(3)) == []


def test_detect_sorts_by_severity_then_time():
    events = fails(12) + [ev(130, SUCCESS)] + [ev(5000 + i * 30, FAILURE, user=f"u{i}", ip="198.51.100.7") for i in range(10)]
    severities = [a.severity for a in detect(events)]
    assert severities == sorted(severities, key=["critical", "high", "medium", "low"].index)


def test_timezone_aware_timestamps():
    lines = [
        f"2026-10-19T04:{m:02d}:00-10:00 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
        for m in range(10)
    ]
    assert len(detect_brute_force(list(parse_lines(lines)))) == 1


def test_empty_input():
    assert detect([]) == []


# end to end on generated logs

@pytest.mark.parametrize("seed", range(25))
def test_finds_every_planted_attack_with_no_false_alarms(seed):
    log = generate(seed=seed, days=2)
    alerts = detect(list(parse_lines(log.lines, default_year=2026)))
    found = {(a.rule, a.src_ip) for a in alerts}
    for attack in log.attacks:
        assert (attack.kind, attack.src_ip) in found
    attacker_ips = {a.src_ip for a in log.attacks}
    assert all(a.src_ip in attacker_ips for a in alerts)


def test_break_in_names_the_compromised_account():
    log = generate(seed=42)
    planted = next(a for a in log.attacks if a.kind == SUCCESS_AFTER_FAILURES)
    alert = next(a for a in detect(list(parse_lines(log.lines, default_year=2026)))
                 if a.rule == SUCCESS_AFTER_FAILURES)
    assert alert.users == (planted.compromised_user,)
    assert alert.end == planted.end
