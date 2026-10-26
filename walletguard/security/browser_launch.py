"""Policy for Chromium browser argument vectors; input must already be tokenized.

The Windows native collector (not implemented here) must use Windows-aware
CommandLineToArgvW or equivalent and never guess based on substrings.
"""
from walletguard.findings import Finding


_RISKY = {
    "--load-extension": ("medium", "Unpacked extension loading flag", "Verify the unpacked extension path and browser build."),
    "--disable-extensions-except": ("medium", "Extensions restriction override", "Verify the explicitly allowed extension and whether this flag was expected."),
    "--remote-debugging-port": ("medium", "Remote debugging enabled", "Disable remote debugging unless required for a trusted development workflow."),
    "--remote-debugging-pipe": ("medium", "Remote debugging pipe enabled", "Confirm a trusted development/debugging process requested this."),
}


def analyze_arguments(args: list[str]) -> list[Finding]:
    """Detect unusual options without treating all development use as malware."""
    findings = []
    seen: set[str] = set()
    for arg in args:
        if not isinstance(arg, str):
            raise TypeError("argument vectors must contain strings")
        if not arg.startswith("--"):
            continue
        flag, _, value = arg.partition("=")
        if flag not in _RISKY or flag in seen:
            continue
        seen.add(flag)
        severity, title, fix = _RISKY[flag]
        findings.append(Finding(
            severity, "browser-launch", title,
            f"Browser launch includes {flag}; context and browser version are not verified.",
            fix, {"flag": flag}))
    return findings
