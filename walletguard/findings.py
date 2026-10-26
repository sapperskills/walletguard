"""A single shared shape for everything the scanner and watchers report."""

from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    severity: str          # critical | high | medium | low | info
    category: str          # defender | extension | startup | task | process | network | wallet
    title: str
    detail: str = ""
    fix: str = ""
    data: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category, f.title))
