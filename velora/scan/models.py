from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SCORE_PENALTY = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}


@dataclass
class Finding:
    category: str      # secret | dependency | config | exposure
    rule: str
    title: str
    severity: str
    file: str = ""
    line: int = 0
    detail: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def location(self) -> str:
        if not self.file:
            return ""
        return f"{self.file}:{self.line}" if self.line else self.file


def at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(severity, 99) <= SEVERITY_RANK.get(threshold, 99)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.category, f.file, f.line))


def security_score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(SCORE_PENALTY.get(f.severity, 0) for f in findings))
