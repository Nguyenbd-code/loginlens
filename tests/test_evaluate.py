from datetime import datetime
from pathlib import Path

from loginlens.detect import BRUTE_FORCE, PASSWORD_SPRAY, Alert, detect
from loginlens.evaluate import evaluate, load_truth, report
from loginlens.parser import parse_file

T = datetime(2026, 10, 12, 3, 0)
SAMPLE = Path(__file__).resolve().parent.parent / "sample"


def alert(rule, ip):
    return Alert(rule, "medium", ip, ("root",), T, T, 10, "test")


TRUTH = [
    {"kind": BRUTE_FORCE, "src_ip": "203.0.113.5"},
    {"kind": PASSWORD_SPRAY, "src_ip": "198.51.100.7"},
]


def test_everything_found():
    result = evaluate([alert(BRUTE_FORCE, "203.0.113.5"), alert(PASSWORD_SPRAY, "198.51.100.7")], TRUTH)
    assert result.passed
    assert len(result.detected) == 2 and result.total == 2


def test_missed_attack():
    result = evaluate([alert(BRUTE_FORCE, "203.0.113.5")], TRUTH)
    assert not result.passed
    assert [m["kind"] for m in result.missed] == [PASSWORD_SPRAY]


def test_wrong_rule_on_right_ip_is_still_a_miss():
    result = evaluate([alert(PASSWORD_SPRAY, "203.0.113.5"), alert(PASSWORD_SPRAY, "198.51.100.7")], TRUTH)
    assert [m["src_ip"] for m in result.missed] == ["203.0.113.5"]
    assert result.false_positives == []  # still a real attacker IP


def test_alert_on_innocent_ip_is_a_false_positive():
    alerts = [alert(BRUTE_FORCE, "203.0.113.5"), alert(PASSWORD_SPRAY, "198.51.100.7"), alert(BRUTE_FORCE, "10.0.0.11")]
    result = evaluate(alerts, TRUTH)
    assert not result.passed
    assert [a.src_ip for a in result.false_positives] == ["10.0.0.11"]


def test_report_text():
    result = evaluate([alert(BRUTE_FORCE, "203.0.113.5"), alert(BRUTE_FORCE, "10.0.0.11")], TRUTH)
    text = report(result)
    assert text.startswith("Detected 1/2 planted attacks, 1 false positive(s)")
    assert "[MISSED] password_spray" in text
    assert "[FALSE]" in text


def test_sample_files_pass():
    events = parse_file(str(SAMPLE / "auth.log"), default_year=2026)
    result = evaluate(detect(events), load_truth(str(SAMPLE / "truth.json")))
    assert result.passed
    assert result.total == 3
