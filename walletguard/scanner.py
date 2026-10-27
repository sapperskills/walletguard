"""The full read-only scan, shared by the CLI and the tray."""

from . import clipboard_history, extensions, integrity, policies, system
from .findings import Finding, sort_findings

# To add a detector: write a module with check() -> [Finding] (see docs/WRITING_A_DETECTOR.md)
# and add it here.
CHECKS = (
    ("extensions", extensions.scan_extensions),
    ("policies", policies.scan_policies),
    ("integrity", integrity.scan_integrity),
    ("clipboard history", clipboard_history.check),
)


def full_scan():
    findings = system.scan_system()
    for name, check in CHECKS:
        try:
            findings += check()
        except Exception as e:  # one broken check must not hide the rest
            findings.append(Finding("low", "scanner", f"{name} check failed", repr(e)))
    return sort_findings(findings)
