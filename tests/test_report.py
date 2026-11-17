from datetime import datetime, timedelta
from pathlib import Path

import pytest

from loginlens.detect import detect
from loginlens.generate import generate
from loginlens.parser import FAILURE, INVALID_USER, SUCCESS, AuthEvent, parse_file, parse_lines
from loginlens.report import build_report, timeline

T0 = datetime(2026, 10, 12, 3, 7, 30)
SAMPLE = Path(__file__).resolve().parent.parent / "sample"


def ev(seconds, outcome, user="root", ip="203.0.113.5"):
    return AuthEvent(T0 + timedelta(seconds=seconds), "web01", outcome, user, ip, 40000,
                     None if outcome == INVALID_USER else "password", outcome == INVALID_USER, "")


# timeline

def test_timeline_starts_on_a_slot_boundary():
    buckets = timeline([ev(0, FAILURE)])
    assert buckets[0].start == datetime(2026, 10, 12, 3, 0)


def test_timeline_counts_failures_and_successes():
    events = [ev(0, FAILURE), ev(60, FAILURE), ev(20 * 60, SUCCESS), ev(21 * 60, INVALID_USER)]
    buckets = timeline(events)
    assert [b.failures for b in buckets] == [2, 0]
    assert [b.successes for b in buckets] == [0, 1]


def test_timeline_covers_the_whole_log():
    events = [ev(0, FAILURE), ev(3 * 3600, FAILURE)]
    buckets = timeline(events)
    assert buckets[-1].start <= T0 + timedelta(hours=3) < buckets[-1].start + timedelta(minutes=15)
    assert sum(b.failures for b in buckets) == 2


def test_timeline_rejects_odd_slot_sizes():
    with pytest.raises(ValueError):
        timeline([ev(0, FAILURE)], minutes=7)


def test_timeline_empty():
    assert timeline([]) == []


# report

@pytest.fixture(scope="module")
def sample_html():
    events = parse_file(str(SAMPLE / "auth.log"), default_year=2026)
    return build_report(events, detect(events), source="sample/auth.log", generated=datetime(2026, 11, 16, 5, 0))


def test_report_is_a_full_page(sample_html):
    assert sample_html.startswith("<!doctype html>")
    assert sample_html.rstrip().endswith("</html>")
    assert "<svg" in sample_html


def test_report_lists_every_alert(sample_html):
    events = parse_file(str(SAMPLE / "auth.log"), default_year=2026)
    for alert in detect(events):
        assert alert.src_ip in sample_html
        assert alert.rule.replace("_", " ") in sample_html


def test_report_puts_the_critical_alert_first(sample_html):
    table = sample_html.split("<h2>Alerts</h2>", 1)[1]
    assert table.index("critical") < table.index("medium")


def test_report_has_no_scripts_or_outside_requests(sample_html):
    assert "<script" not in sample_html.lower()
    assert "http://" not in sample_html and "https://" not in sample_html


def test_attacker_controlled_usernames_are_escaped():
    # sshd logs whatever username an attacker sends, including HTML
    evil = '<script>alert(1)</script>'
    lines = [
        f"Oct 12 03:0{i}:00 web01 sshd[1]: Invalid user {evil}{i} from 203.0.113.9 port 4000"
        for i in range(10)
    ] + [
        f"Oct 12 03:0{i}:01 web01 sshd[1]: Failed password for invalid user {evil}{i} from 203.0.113.9 port 4000 ssh2"
        for i in range(10)
    ]
    events = list(parse_lines(lines, default_year=2026))
    page = build_report(events, detect(events))
    assert "<script" not in page
    assert "&lt;script&gt;" in page


def test_source_and_title_are_escaped():
    page = build_report([], [], source='<img src=x onerror=alert(1)>', title="<b>hi</b>")
    assert "<img" not in page and "<b>hi" not in page


def test_report_of_empty_log():
    page = build_report([], [])
    assert "No attacks detected." in page
    assert "no login attempts found" in page


def test_clean_log_shows_no_attacks():
    events = [ev(0, SUCCESS, user="alice", ip="10.0.0.11")]
    assert "No attacks detected." in build_report(events, detect(events))


def test_multi_day_report_labels_dates():
    log = generate(seed=3, days=3)
    events = list(parse_lines(log.lines, default_year=2026))
    page = build_report(events, detect(events))
    assert "10/13" in page  # x-axis switches to month/day when the log spans days
