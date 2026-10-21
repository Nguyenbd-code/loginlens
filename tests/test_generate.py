import json
from collections import Counter
from datetime import datetime

import pytest

from loginlens.generate import (
    BRUTE_FORCE,
    PASSWORD_SPRAY,
    SUCCESS_AFTER_FAILURES,
    generate,
)
from loginlens.parser import FAILURE, SUCCESS, parse_lines


@pytest.fixture(scope="module")
def sample():
    return generate(seed=42)


@pytest.fixture(scope="module")
def events(sample):
    return list(parse_lines(sample.lines, default_year=2026))


def attack(sample, kind):
    return next(a for a in sample.attacks if a.kind == kind)


def test_same_seed_gives_same_log():
    assert generate(seed=7).lines == generate(seed=7).lines


def test_different_seed_gives_different_log():
    assert generate(seed=7).lines != generate(seed=8).lines


def test_every_line_is_parseable_or_known_noise(sample):
    # Each generated line is either a login attempt the parser understands,
    # or one of the session/connection lines it deliberately skips.
    skipped_prefixes = ("Connection closed by", "pam_unix(sshd:session)", "Received disconnect")
    for line in sample.lines:
        message = line.split(": ", 1)[1]
        if not list(parse_lines([line], default_year=2026)):
            assert message.startswith(skipped_prefixes), line


def test_lines_are_in_time_order(events):
    times = [e.timestamp for e in events]
    assert times == sorted(times)


def test_one_of_each_attack_is_planted(sample):
    assert sorted(a.kind for a in sample.attacks) == sorted([BRUTE_FORCE, PASSWORD_SPRAY, SUCCESS_AFTER_FAILURES])


def test_attackers_use_documentation_ip_ranges(sample):
    for a in sample.attacks:
        assert a.src_ip.startswith(("203.0.113.", "198.51.100."))


def test_brute_force_matches_ground_truth(sample, events):
    a = attack(sample, BRUTE_FORCE)
    from_ip = [e for e in events if e.src_ip == a.src_ip]
    assert len(from_ip) == a.attempts
    assert {e.user for e in from_ip} == {"root"}
    assert all(e.outcome == FAILURE for e in from_ip)
    assert from_ip[0].timestamp == a.start


def test_password_spray_hits_many_accounts(sample, events):
    a = attack(sample, PASSWORD_SPRAY)
    from_ip = [e for e in events if e.src_ip == a.src_ip]
    assert {e.user for e in from_ip} == set(a.users)
    assert len(a.users) >= 20
    # Spraying means few guesses per account, not many guesses on one.
    password_tries = Counter(e.user for e in from_ip if e.outcome == FAILURE)
    assert max(password_tries.values()) == 1
    assert all(e.is_failure for e in from_ip)


def test_success_after_failures_ends_in_a_login(sample, events):
    a = attack(sample, SUCCESS_AFTER_FAILURES)
    from_ip = [e for e in events if e.src_ip == a.src_ip]
    assert len(from_ip) == a.attempts
    assert from_ip[-1].outcome == SUCCESS
    assert from_ip[-1].user == a.compromised_user
    assert all(e.outcome == FAILURE for e in from_ip[:-1])
    assert from_ip[-1].timestamp == a.end


def test_normal_traffic_has_benign_failures(events, sample):
    # A realistic log has some harmless failures (typos, scanner noise),
    # so detectors can't just flag every failure.
    attacker_ips = {a.src_ip for a in sample.attacks}
    benign_failures = [e for e in events if e.is_failure and e.src_ip not in attacker_ips]
    assert benign_failures
    assert any(e.outcome == SUCCESS and e.src_ip not in attacker_ips for e in events)


def test_scanner_noise_stays_small_per_ip(events, sample):
    attacker_ips = {a.src_ip for a in sample.attacks}
    per_ip = Counter(e.src_ip for e in events if e.is_failure and e.src_ip not in attacker_ips)
    assert max(per_ip.values()) <= 4


def test_multi_day_log_spans_the_days():
    log = generate(seed=1, start=datetime(2026, 10, 12), days=3)
    days_seen = {e.timestamp.date() for e in parse_lines(log.lines, default_year=2026)}
    assert len(days_seen) == 3


def test_days_must_be_positive():
    with pytest.raises(ValueError):
        generate(days=0)


def test_truth_json_round_trips(sample):
    data = json.loads(sample.truth_json())
    assert [d["kind"] for d in data] == [a.kind for a in sample.attacks]
    assert all(datetime.fromisoformat(d["start"]) for d in data)
