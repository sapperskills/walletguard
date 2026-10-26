"""The full read-only scan, shared by the CLI and the tray."""

from . import extensions, integrity, policies, system
from .findings import Finding, sort_findings


def full_scan():
    findings = system.scan_system()
    for name, check in (("extensions", extensions.scan_extensions),
                        ("policies", policies.scan_policies),
                        ("integrity", integrity.scan_integrity)):
        try:
            findings += check()
        except Exception as e:  # one broken check must not hide the rest
            findings.append(Finding("low", "scanner", f"{name} check failed", repr(e)))
    return sort_findings(findings)
