"""Privacy-preserving connection origin hints. No domain reputation checks."""
from urllib.parse import urlsplit
from walletguard.findings import Finding


def analyze_origin(origin: str) -> list[Finding]:
    if not isinstance(origin, str):
        raise ValueError("origin must be a URL string")
    try:
        parts = urlsplit(origin)
        host = parts.hostname
        port = parts.port  # validate invalid ports
    except ValueError:
        raise ValueError("invalid URL") from None
    if not host or parts.scheme not in {"https", "http"}:
        return [Finding("high", "origin", "Unsupported connection origin",
                        "Only well-formed HTTP(S) web origins are expected here.",
                        "Reject connection requests from unexpected origin schemes.")]
    if parts.username or parts.password:
        return [Finding("high", "origin", "Credentials embedded in site URL",
                        "The displayed host can be misleading when URL user information is present.",
                        "Do not approve; independently navigate to the intended site.")]
    findings = []
    if parts.scheme == "http":
        local = host.lower() in {"localhost", "127.0.0.1", "[::1]", "::1"}
        findings.append(Finding(
            "low" if local else "high", "origin", "Unencrypted website origin",
            "The connection does not use HTTPS; localhost may be legitimate for development.",
            "Prefer an authenticated HTTPS site; verify local development sessions."))
    if "xn--" in host.lower():
        findings.append(Finding("medium", "origin", "Internationalized domain encoding",
                                "The hostname includes punycode; this alone does not establish phishing.",
                                "Inspect the actual domain carefully and compare with the intended site."))
    if not findings:
        findings.append(Finding("info", "scope", "No origin warning detected",
                                "No reputation lookup or contract inspection was performed.",
                                "Verify the site identity, wallet permissions and transaction independently."))
    return findings
