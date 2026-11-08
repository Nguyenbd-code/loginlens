"""Score alerts against the ground truth written by the generator.

A planted attack counts as detected when an alert from the matching rule
fires on the attacker's IP. Any alert on an IP that isn't a planted
attacker is a false positive.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .detect import Alert


@dataclass
class Evaluation:
    detected: list[tuple[dict, Alert]] = field(default_factory=list)
    missed: list[dict] = field(default_factory=list)
    false_positives: list[Alert] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.detected) + len(self.missed)

    @property
    def passed(self) -> bool:
        return not self.missed and not self.false_positives


def load_truth(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def evaluate(alerts: list[Alert], truth: list[dict]) -> Evaluation:
    result = Evaluation()
    for attack in truth:
        match = next((a for a in alerts if a.rule == attack["kind"] and a.src_ip == attack["src_ip"]), None)
        if match:
            result.detected.append((attack, match))
        else:
            result.missed.append(attack)
    attacker_ips = {a["src_ip"] for a in truth}
    result.false_positives = [a for a in alerts if a.src_ip not in attacker_ips]
    return result


def report(result: Evaluation) -> str:
    rows = [f"Detected {len(result.detected)}/{result.total} planted attacks, "
            f"{len(result.false_positives)} false positive(s)", ""]
    for attack, alert in result.detected:
        rows.append(f"  [found]  {attack['kind']:<24} {attack['src_ip']:<16} {alert.summary}")
    for attack in result.missed:
        rows.append(f"  [MISSED] {attack['kind']:<24} {attack['src_ip']}")
    for alert in result.false_positives:
        rows.append(f"  [FALSE]  {alert.rule:<24} {alert.src_ip:<16} {alert.summary}")
    return "\n".join(rows)
