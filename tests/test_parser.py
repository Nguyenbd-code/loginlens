from datetime import datetime, timedelta, timezone

from loginlens.parser import (
    FAILURE,
    INVALID_USER,
    SUCCESS,
    parse_file,
    parse_line,
    parse_lines,
)


def one(line, year=2026):
    events = parse_line(line, default_year=year)
    assert len(events) == 1, f"expected one event from: {line}"
    return events[0]


def test_failed_password_known_user():
    e = one("Oct 19 04:01:02 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52345 ssh2")
    assert e.outcome == FAILURE
    assert e.user == "root"
    assert e.src_ip == "203.0.113.5"
    assert e.port == 52345
    assert e.method == "password"
    assert e.invalid_user is False
    assert e.host == "web01"
    assert e.timestamp == datetime(2026, 10, 19, 4, 1, 2)
    assert e.is_failure


def test_failed_password_invalid_user():
    e = one("Oct 19 04:01:03 web01 sshd[1235]: Failed password for invalid user admin from 203.0.113.5 port 52346 ssh2")
    assert e.outcome == FAILURE
    assert e.user == "admin"
    assert e.invalid_user is True


def test_invalid_user_line():
    e = one("Oct 19 04:01:03 web01 sshd[1235]: Invalid user oracle from 198.51.100.7 port 40000")
    assert e.outcome == INVALID_USER
    assert e.user == "oracle"
    assert e.src_ip == "198.51.100.7"
    assert e.port == 40000
    assert e.method is None
    assert e.is_failure


def test_invalid_user_line_without_port():
    # Older OpenSSH versions leave the port off this message.
    e = one("Oct 19 04:01:03 web01 sshd[1235]: Invalid user test from 198.51.100.7")
    assert e.port is None


def test_accepted_publickey_with_key_fingerprint():
    e = one(
        "Oct 19 09:15:00 web01 sshd[2001]: Accepted publickey for brandon from 10.0.0.5 "
        "port 51234 ssh2: ED25519 SHA256:abc123def456"
    )
    assert e.outcome == SUCCESS
    assert e.user == "brandon"
    assert e.method == "publickey"
    assert not e.is_failure


def test_accepted_password():
    e = one("Oct 19 09:16:00 web01 sshd[2002]: Accepted password for alice from 192.168.1.20 port 60000 ssh2")
    assert e.outcome == SUCCESS
    assert e.method == "password"


def test_ipv6_source():
    e = one("Oct 19 09:16:00 web01 sshd[2002]: Failed password for root from 2001:db8::1 port 60000 ssh2")
    assert e.src_ip == "2001:db8::1"


def test_single_digit_day_is_space_padded():
    e = one("Oct  5 01:02:03 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2")
    assert e.timestamp == datetime(2026, 10, 5, 1, 2, 3)


def test_iso_timestamp_keeps_timezone():
    e = one(
        "2026-10-19T04:01:02.123456-10:00 web01 sshd[1234]: "
        "Failed password for root from 203.0.113.5 port 52345 ssh2"
    )
    assert e.timestamp.tzinfo is not None
    assert e.timestamp.utcoffset() == timedelta(hours=-10)
    assert e.timestamp.astimezone(timezone.utc).hour == 14


def test_message_repeated_expands_into_multiple_events():
    events = parse_line(
        "Oct 19 04:02:00 web01 sshd[1240]: message repeated 3 times: "
        "[ Failed password for root from 203.0.113.5 port 52350 ssh2]",
        default_year=2026,
    )
    assert len(events) == 3
    assert all(e.outcome == FAILURE and e.user == "root" for e in events)


def test_username_with_spaces_is_kept_whole():
    # Attackers sometimes send odd usernames; the parser shouldn't split them.
    e = one("Oct 19 04:01:03 web01 sshd[1235]: Invalid user john smith from 203.0.113.9 port 4000")
    assert e.user == "john smith"


def test_ignores_non_login_sshd_lines():
    lines = [
        "Oct 19 04:01:04 web01 sshd[1234]: Connection closed by authenticating user root 203.0.113.5 port 52345 [preauth]",
        "Oct 19 04:01:04 web01 sshd[1234]: Disconnected from invalid user admin 203.0.113.5 port 52346 [preauth]",
        "Oct 19 09:15:00 web01 sshd[2001]: pam_unix(sshd:session): session opened for user brandon(uid=1000) by (uid=0)",
        "Oct 19 09:15:00 web01 sshd[2001]: Received disconnect from 10.0.0.5 port 51234:11: disconnected by user",
    ]
    assert list(parse_lines(lines, default_year=2026)) == []


def test_ignores_other_programs():
    assert parse_line("Oct 19 04:01:02 web01 sudo[99]: Failed password for root from 203.0.113.5 port 1 ssh2") == []
    assert parse_line("Oct 19 04:01:02 web01 CRON[99]: pam_unix(cron:session): session opened for user root") == []


def test_ignores_garbage_and_blank_lines():
    assert parse_line("") == []
    assert parse_line("not a log line at all") == []
    assert parse_line("Oct 19 04:01:02 web01 sshd[1]: Failed password for root from not-an-ip port 1 ssh2") == []


def test_ignores_impossible_dates():
    assert parse_line("Feb 30 04:01:02 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2") == []


def test_raw_line_is_kept_without_newline():
    line = "Oct 19 04:01:02 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52345 ssh2\n"
    assert one(line).raw == line.rstrip("\n")


def test_parse_file(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Oct 19 04:01:02 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2\n"
        "Oct 19 04:01:03 web01 sshd[1]: Connection closed by 203.0.113.5 port 1 [preauth]\n"
        "Oct 19 09:15:00 web01 sshd[2]: Accepted publickey for brandon from 10.0.0.5 port 2 ssh2\n",
        encoding="utf-8",
    )
    events = parse_file(str(log), default_year=2026)
    assert [e.outcome for e in events] == [FAILURE, SUCCESS]
