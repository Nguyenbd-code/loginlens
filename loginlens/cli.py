"""Command-line interface.

    loginlens generate --out sample/auth.log --truth sample/truth.json
    loginlens summary sample/auth.log
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .generate import generate
from .parser import FAILURE, INVALID_USER, SUCCESS, AuthEvent, parse_file


def _cmd_generate(args: argparse.Namespace) -> int:
    log = generate(seed=args.seed, start=datetime.fromisoformat(args.start), days=args.days)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(log.lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(log.lines)} lines to {out}")
    if args.truth:
        truth = Path(args.truth)
        truth.parent.mkdir(parents=True, exist_ok=True)
        truth.write_text(log.truth_json(), encoding="utf-8")
        print(f"Wrote {len(log.attacks)} planted attacks to {truth}")
    return 0


def summarize(events: list[AuthEvent], top: int = 5) -> str:
    if not events:
        return "No SSH login attempts found."
    outcomes = Counter(e.outcome for e in events)
    failures = [e for e in events if e.is_failure]
    first, last = min(e.timestamp for e in events), max(e.timestamp for e in events)

    rows = [
        f"Login attempts:   {len(events)}",
        f"Time range:       {first:%Y-%m-%d %H:%M:%S} to {last:%Y-%m-%d %H:%M:%S}",
        f"Successful:       {outcomes[SUCCESS]}",
        f"Failed password:  {outcomes[FAILURE]}",
        f"Invalid user:     {outcomes[INVALID_USER]}",
        f"Source IPs:       {len({e.src_ip for e in events})}",
    ]
    if failures:
        width = max(len(ip) for ip, _ in Counter(e.src_ip for e in failures).most_common(top))
        rows += ["", f"Top {top} IPs by failed attempts:"]
        for ip, n in Counter(e.src_ip for e in failures).most_common(top):
            rows.append(f"  {ip:<{width}}  {n}")
        rows += ["", f"Top {top} targeted usernames:"]
        for user, n in Counter(e.user for e in failures).most_common(top):
            rows.append(f"  {user:<{width}}  {n}")
    return "\n".join(rows)


def _cmd_summary(args: argparse.Namespace) -> int:
    path = Path(args.logfile)
    if not path.is_file():
        print(f"loginlens: no such file: {path}", file=sys.stderr)
        return 1
    events = parse_file(str(path), default_year=args.year)
    print(summarize(events, top=args.top))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loginlens", description="Find attacks hiding in Linux SSH login logs.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="write a fake auth.log with attacks planted in it")
    gen.add_argument("--out", default="sample/auth.log", help="where to write the log (default: %(default)s)")
    gen.add_argument("--truth", help="also write the planted attacks as JSON to this path")
    gen.add_argument("--seed", type=int, default=42, help="random seed (default: %(default)s)")
    gen.add_argument("--days", type=int, default=1, help="how many days of traffic (default: %(default)s)")
    gen.add_argument("--start", default="2026-10-12", help="first day, YYYY-MM-DD (default: %(default)s)")
    gen.set_defaults(func=_cmd_generate)

    summ = sub.add_parser("summary", help="count login attempts in a log file")
    summ.add_argument("logfile", help="path to an auth.log file")
    summ.add_argument("--year", type=int, default=None,
                      help="year for timestamps that don't include one (default: this year)")
    summ.add_argument("--top", type=int, default=5, help="how many IPs and usernames to list (default: %(default)s)")
    summ.set_defaults(func=_cmd_summary)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
