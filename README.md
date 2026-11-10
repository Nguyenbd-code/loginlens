# LoginLens

Find brute-force and password-spraying attacks in Linux SSH login logs.

Every Linux server that's reachable from the internet gets SSH login attempts from strangers all day. Most of it is harmless background noise, but some of it is a real attack: someone guessing one account's password over and over, or trying a few common passwords across every account they can think of. LoginLens reads the server's login log (`/var/log/auth.log`), turns each line into a structured event, and pulls out the activity worth looking at.

> **Status:** in progress. Parsing, detection and evaluation work; a web dashboard is next (see [Roadmap](#roadmap)).

## Quick start

Requires Python 3.10 or newer. There are no runtime dependencies.

```bash
git clone https://github.com/Nguyenbd-code/loginlens.git
cd loginlens
pip install -e ".[dev]"

loginlens detect sample/auth.log --year 2026
```

Output on the included sample log:

```
4 alert(s)

[CRITICAL] success_after_failures   203.0.113.135    2026-10-12 21:59:50
           'leilani' logged in after 36 failed attempts from this IP  (accounts: leilani)
[HIGH    ] password_spray           198.51.100.79    2026-10-12 15:52:31
           23 different accounts tried in 24 min  (accounts: alice, demo, dev +20 more)
[MEDIUM  ] brute_force              203.0.113.45     2026-10-12 01:03:35
           60 failed passwords for 'root' in 3 min  (accounts: root)
[MEDIUM  ] brute_force              203.0.113.135    2026-10-12 21:59:50
           36 failed passwords for 'leilani' in 2 min  (accounts: leilani)
```

The break-in shows up twice on purpose: it was a brute force that worked, so it trips both rules, and the critical alert goes to the top.

For plain counts instead of alerts, use `summary`:

```bash
loginlens summary sample/auth.log --year 2026
```

Example summary output:

```
Login attempts:   161
Time range:       2026-10-12 00:05:05 to 2026-10-12 23:54:50
Successful:       26
Failed:           135
Unknown users:    32
Source IPs:       20

Top 5 IPs by failed attempts:
  203.0.113.45   60
  203.0.113.135  36
  198.51.100.79  23
  192.0.2.79     2
  192.0.2.177    2

Top 5 targeted usernames:
  root           64
  leilani        37
  test           6
  admin          4
  ubuntu         4
```

The top three IPs are the attacks planted in the sample. The rest is ordinary scanner noise.

## How it works

**1. Parsing** ([`loginlens/parser.py`](loginlens/parser.py))

The SSH server writes lines like this:

```
Oct 12 01:03:35 web01 sshd[4491]: Failed password for root from 203.0.113.45 port 55620 ssh2
Oct 12 01:03:38 web01 sshd[4491]: message repeated 2 times: [ Failed password for root from 203.0.113.45 port 55620 ssh2]
Oct 12 09:14:02 web01 sshd[4620]: Accepted publickey for brandon from 10.0.0.11 port 40112 ssh2: ED25519 SHA256:...
```

The parser turns each login attempt into an `AuthEvent` with a timestamp, username, source IP, outcome (`success`, `failure` or `invalid_user`) and the original line kept as evidence. It handles both the classic syslog timestamp and the newer ISO 8601 format, expands `message repeated N times` lines into N events, validates IP addresses (IPv4 and IPv6), and skips lines that aren't login attempts.

**2. Sample data** ([`loginlens/generate.py`](loginlens/generate.py))

Real server logs contain real usernames and IP addresses, so they don't belong in a public repo. LoginLens includes a generator that writes a realistic day on a small server: staff logging in (sometimes after a typo), a deploy bot, a nightly backup, and internet scanners that try once or twice and leave. Then it hides three known attacks in that traffic:

| Attack | What it looks like in the log |
| --- | --- |
| Brute force | One IP, one account, dozens of wrong passwords in a few minutes |
| Password spraying | One IP, a couple dozen different accounts, one guess each, spread out slowly to avoid lockouts |
| Success after failures | Many failed guesses on one account, then a login that worked. The attacker got in. |

Because the attacks are planted, the generator also writes the right answer to [`sample/truth.json`](sample/truth.json), which the detection rules are graded against. The output is seeded, so the same seed always produces the same log.

```bash
loginlens generate --out my.log --truth my-truth.json --seed 7 --days 3
```

Attacker IPs use the ranges reserved for documentation (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`), so none of them belong to anyone real.

**3. Detection** ([`loginlens/detect.py`](loginlens/detect.py))

Each rule looks at activity from one source IP inside a sliding time window:

| Rule | Fires when | Default threshold | Severity |
| --- | --- | --- | --- |
| Brute force | Many failed passwords on **one** account | 10 failures in 10 min | Medium |
| Password spraying | Failures across **many** accounts | 10 accounts in 1 hour | High |
| Success after failures | A login that worked right after a run of failures from the same IP | 5 failures in the 30 min before | Critical |

A long attack produces one alert, not one per window, and a staff member who mistypes once and then logs in doesn't trigger anything. Thresholds live in `DetectionConfig` and can be tuned.

**4. Evaluation** ([`loginlens/evaluate.py`](loginlens/evaluate.py))

`evaluate` runs detection and compares the alerts against the ground truth: every planted attack should be caught by the right rule, and no alert should land on an innocent IP.

```
$ loginlens evaluate sample/auth.log sample/truth.json --year 2026
Detected 3/3 planted attacks, 0 false positive(s)

  [found]  brute_force              203.0.113.45     60 failed passwords for 'root' in 3 min
  [found]  password_spray           198.51.100.79    23 different accounts tried in 24 min
  [found]  success_after_failures   203.0.113.135    'leilani' logged in after 36 failed attempts from this IP
```

It exits with code 2 if anything is missed or falsely flagged, so it can run in CI.

## Running the tests

```bash
pytest
```

The tests cover each log format the parser understands and the lines it should ignore, each detection rule's thresholds and edge cases (typos, slow attacks, timezones), and an end-to-end check that detection finds every planted attack with no false alarms across 25 different generated logs.

## Roadmap

- [x] Parse SSH login lines from `auth.log`
- [x] Generate sample logs with planted attacks and ground truth
- [x] `summary` command
- [x] Detection rules: brute force, password spraying, success after failures
- [x] `evaluate` command to grade detection against ground truth
- [ ] Web dashboard with a timeline of attacks
- [ ] Map findings to MITRE ATT&CK techniques
