# LoginLens

Find brute-force and password-spraying attacks in Linux SSH login logs.

Every Linux server that's reachable from the internet gets SSH login attempts from strangers all day. Most of it is harmless background noise, but some of it is a real attack: someone guessing one account's password over and over, or trying a few common passwords across every account they can think of. LoginLens reads the server's login log (`/var/log/auth.log`), turns each line into a structured event, and pulls out the activity worth looking at.

> **Status:** in progress. The parser, sample-log generator and summary command are done. Detection rules come next (see [Roadmap](#roadmap)).

## Quick start

Requires Python 3.10 or newer. There are no runtime dependencies.

```bash
git clone https://github.com/Nguyenbd-code/loginlens.git
cd loginlens
pip install -e ".[dev]"

loginlens summary sample/auth.log --year 2026
```

Example output from the included sample log:

```
Login attempts:   193
Time range:       2026-10-12 00:05:05 to 2026-10-12 23:54:50
Successful:       26
Failed password:  135
Invalid user:     32
Source IPs:       20

Top 5 IPs by failed attempts:
  203.0.113.45   60
  198.51.100.79  43
  203.0.113.135  36
  192.0.2.177    4
  192.0.2.28     4

Top 5 targeted usernames:
  root           64
  leilani        37
  test           12
  admin          8
  ubuntu         8
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

Because the attacks are planted, the generator also writes the right answer to [`sample/truth.json`](sample/truth.json). That's what the detection rules will be tested against. The output is seeded, so the same seed always produces the same log.

```bash
loginlens generate --out my.log --truth my-truth.json --seed 7 --days 3
```

Attacker IPs use the ranges reserved for documentation (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`), so none of them belong to anyone real.

## Running the tests

```bash
pytest
```

The tests cover each log format the parser understands, lines it should ignore, and checks that the generated log matches its own ground truth.

## Roadmap

- [x] Parse SSH login lines from `auth.log`
- [x] Generate sample logs with planted attacks and ground truth
- [x] `summary` command
- [ ] Detection rules: brute force, password spraying, success after failures
- [ ] Web dashboard with a timeline of attacks
- [ ] Map findings to MITRE ATT&CK techniques
