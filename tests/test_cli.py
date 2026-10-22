import json

from loginlens.cli import main, summarize
from loginlens.parser import parse_lines


def test_generate_writes_log_and_truth(tmp_path, capsys):
    out, truth = tmp_path / "auth.log", tmp_path / "truth.json"
    assert main(["generate", "--out", str(out), "--truth", str(truth), "--seed", "3"]) == 0
    assert out.read_text().count("\n") > 100
    assert len(json.loads(truth.read_text())) == 3
    assert "Wrote" in capsys.readouterr().out


def test_summary_reports_counts(tmp_path, capsys):
    out = tmp_path / "auth.log"
    main(["generate", "--out", str(out)])
    capsys.readouterr()
    assert main(["summary", str(out), "--year", "2026"]) == 0
    text = capsys.readouterr().out
    assert "Login attempts:" in text
    assert "Top 5 IPs by failed attempts:" in text


def test_summary_missing_file(tmp_path, capsys):
    assert main(["summary", str(tmp_path / "nope.log")]) == 1
    assert "no such file" in capsys.readouterr().err


def test_summary_top_ip_is_the_biggest_attacker():
    lines = (
        ["Oct 19 04:01:0%d web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2" % i for i in range(5)]
        + ["Oct 19 04:02:00 web01 sshd[2]: Failed password for root from 192.0.2.9 port 1 ssh2"]
    )
    text = summarize(list(parse_lines(lines, default_year=2026)), top=1)
    assert "203.0.113.5  5" in text
    assert "192.0.2.9" not in text


def test_summary_counts_invalid_user_guess_once():
    lines = [
        "Oct 19 04:01:00 web01 sshd[1]: Invalid user oracle from 198.51.100.7 port 4000",
        "Oct 19 04:01:01 web01 sshd[1]: Failed password for invalid user oracle from 198.51.100.7 port 4000 ssh2",
    ]
    text = summarize(list(parse_lines(lines, default_year=2026)))
    assert "Login attempts:   1" in text
    assert "198.51.100.7  1" in text


def test_summary_of_empty_log():
    assert summarize([]) == "No SSH login attempts found."
