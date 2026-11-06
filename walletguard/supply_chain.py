"""Read-only, bounded package metadata collection and pure supply-chain heuristics.

No package code, npm configuration, Git configuration or lockfiles are opened.
Self-reported repository/publisher metadata is a clue, never authentication.
"""

import json
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

from .findings import Finding

LIMIT = 512 * 1024
MAX_PACKAGES = 2000
RECENT_SECONDS = 7 * 86400
SHELL = re.compile(r"\b(?:powershell|pwsh|cmd(?:\.exe)?|bash|sh|wscript|cscript|mshta)\b|child_process|execSync|spawn\s*\(", re.I)
DOWNLOAD = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|Start-BitsTransfer)\b|https?://[^\s]+\.(?:exe|msi|dll)\b|DownloadFile|DownloadString", re.I)
SCRIPT = re.compile(r"\.(?:ps1|vbs|js|cmd|bat)\b", re.I)


def trusted_dev(text):
    text = text.lower().replace('/', '\\')
    return (bool(re.search(r"(?:^|[\s\"'])c:\\dev(?:\\|[\s\"']|$)", text))
            or bool(re.search(r"(?:^|[\\\s])(?:cutshit|ollama|electron)(?:[\\\s.-]|$)", text)))


def repository_id(value):
    """Discard credentials, query and fragment; return only a public repository identity."""
    if not isinstance(value, str):
        return ''
    value = value.removeprefix('git+')
    if value.startswith('git@github.com:'):
        value = 'https://github.com/' + value.split(':', 1)[1]
    try:
        url = urlsplit(value)
        if not url.hostname:
            return ''
        return (url.hostname + url.path).lower().rstrip('/').removesuffix('.git')
    except ValueError:
        return ''


def near_name(name, official):
    """One insertion/deletion/substitution/transposition, including scope impersonation."""
    a, b = name.lower(), official.lower()
    if a == b:
        return False
    a, b = a.rsplit('/', 1)[-1], b.rsplit('/', 1)[-1]
    if a == b:
        return True
    if len(b) < 5 or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diffs) == 1 or (len(diffs) == 2 and diffs[1] == diffs[0] + 1
                                  and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]])
    short, long = sorted((a, b), key=len)
    return any(long[:i] + long[i + 1:] == short for i in range(len(long)))


def assess(packages, entries, allowlist):
    """Pure assessment of projected metadata; commands/scripts never enter findings."""
    findings = []
    for p in packages:
        name = p.get('name', '')
        rule = allowlist.get(name)
        reasons = []
        if rule is None and any(near_name(name, n) for n in allowlist):
            reasons.append('name closely imitates an official package')
        if rule is not None:
            if p.get('repository') and rule.get('repositories') and p['repository'] not in rule['repositories']:
                reasons.append('claimed repository differs from the official source')
            if p.get('publisher') and rule.get('publishers') and p['publisher'] not in rule['publishers']:
                reasons.append('claimed publisher differs from the allowlist')
        if p.get('recent') and p.get('shell'):
            reasons.append('recent package metadata has a shell-spawning install hook')
        if p.get('recent') and p.get('download'):
            reasons.append('recent package metadata has a download-capable install hook')
        if not reasons:
            continue
        dev = trusted_dev(p.get('path', ''))
        severity = ('high' if len(reasons) >= 3 else 'medium' if len(reasons) >= 1 else 'low')
        if dev and len(reasons) < 3:
            severity = 'low'
        findings.append(Finding(severity, 'supply-chain', 'Review developer package',
            '; '.join(reasons) + '. These indicators can expose wallet data if malicious code runs. '
            'Known false positives: forks, local development packages and legitimate native installers.',
            fix='Review the package at the reported path against the official project website and publisher. '
                'If unrecognised, stop using it and remove it through your package manager after review.',
            data={'path': p.get('path', ''), 'indicators': reasons}))
    for entry in entries:
        command = entry.get('command', '')
        lower = command.lower().replace('/', '\\')
        writable = bool(re.search(r"\\(?:users|temp|appdata|dev)\\|%(?:appdata|localappdata|temp|userprofile)%", lower))
        hidden = bool(re.search(r"-(?:w(?:indowstyle)?)\s+hidden\b|//b\b", command, re.I))
        unusual = bool(re.search(r"-enc(?:odedcommand)?\b|\bbypass\b|\\temp\\|\\\.\w", lower))
        if not (SCRIPT.search(command) and writable and (hidden or unusual)):
            continue
        extra = bool(DOWNLOAD.search(command))
        severity = 'high' if hidden and unusual and extra else 'medium'
        if trusted_dev(command) and not (hidden and unusual and extra):
            severity = 'low'
        findings.append(Finding(severity, 'supply-chain', 'Review script startup entry',
            'A Run-key entry launches a script in a user-writable folder with hidden or unusual options. '
            'It could run unwanted code at logon. Known false positives: PowerShell automation and developer launchers.',
            fix='Review this Run-key value in Registry Editor and the script path. If unrecognised, disable '
                'the startup item in Task Manager and scan it with Windows Security.',
            data={'source': entry.get('source', ''), 'index': entry.get('index', 0)}))
    return findings


def _read_json(path):
    if _redirected(path) or path.stat().st_size > LIMIT:
        raise ValueError('metadata unavailable')
    with path.open(encoding='utf-8-sig') as stream:
        contents = stream.read(LIMIT + 1)
    if len(contents) > LIMIT:
        raise ValueError('metadata unavailable')
    value = json.loads(contents)
    if not isinstance(value, dict):
        raise ValueError('metadata unavailable')
    return value


def _redirected(path):
    """Skip symlinks and Windows junctions instead of following them outside scope."""
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _manifests(root):
    """Only immediate packages (including scoped packages); never recurse dependencies."""
    if not root.is_dir() or _redirected(root):
        return
    for child in root.iterdir():
        if _redirected(child) or not child.is_dir():
            continue
        if child.name.startswith('@'):
            for scoped in child.iterdir():
                if scoped.is_dir() and not _redirected(scoped):
                    yield scoped / 'package.json'
        else:
            yield child / 'package.json'


def collect_packages(roots, now=None, repo_manifests=()):
    """Explicit roots make fixture testing independent of the live machine."""
    now = time.time() if now is None else now
    packages, errors = [], 0
    seen = set()
    for root in [*roots, None]:
        try:
            for manifest in (repo_manifests if root is None else _manifests(Path(root))):
                if str(manifest) in seen:
                    continue
                seen.add(str(manifest))
                if len(seen) > MAX_PACKAGES:
                    return packages, errors + 1
                try:
                    p = _read_json(manifest)
                    scripts = p.get('scripts', {})
                    hooks = ' '.join(v for k, v in scripts.items()
                                     if k in ('preinstall', 'install', 'postinstall') and isinstance(v, str)) if isinstance(scripts, dict) else ''
                    repo = p.get('repository', '')
                    repo = repo.get('url', '') if isinstance(repo, dict) else repo
                    publisher = p.get('_npmUser', {})
                    name = p.get('name', '')
                    packages.append({'path': str(manifest), 'name': name if isinstance(name, str) else '',
                        'repository': repository_id(repo),
                        'publisher': publisher.get('name', '') if isinstance(publisher, dict) else '',
                        'recent': 0 <= now - manifest.stat().st_mtime <= RECENT_SECONDS,
                        'shell': bool(SHELL.search(hooks)), 'download': bool(DOWNLOAD.search(hooks))})
                except (OSError, ValueError, TypeError, RecursionError):
                    errors += 1
        except OSError:
            errors += 1
    return packages, errors


def read_run_entries():
    import winreg
    entries, errors = [], 0
    seen = set()
    for hive, label in ((winreg.HKEY_CURRENT_USER, 'HKCU'), (winreg.HKEY_LOCAL_MACHINE, 'HKLM')):
        for suffix in ('Run', 'RunOnce'):
            key = 'Software\\Microsoft\\Windows\\CurrentVersion\\' + suffix
            for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
                try:
                    with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | view) as handle:
                        count = winreg.QueryInfoKey(handle)[1]
                        if count > MAX_PACKAGES:
                            errors += 1
                        for i in range(min(count, MAX_PACKAGES)):
                            _, value, kind = winreg.EnumValue(handle, i)
                            if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                                identity = (label, key, value)
                                if identity in seen:
                                    continue
                                seen.add(identity)
                                entries.append({'source': label + '\\' + key + f' (view {view})',
                                                'index': i, 'command': value})
                except FileNotFoundError:
                    pass
                except OSError:
                    errors += 1
    return entries, errors


def check():
    allowlist = _read_json(Path(__file__).with_name('supply_chain_allowlist.json'))
    roots = []
    for env, suffix in (('APPDATA', 'npm/node_modules'), ('ProgramFiles', 'nodejs/node_modules'),
                        ('NPM_CONFIG_PREFIX', 'node_modules')):
        if os.environ.get(env):
            roots.append(Path(os.environ[env]) / suffix)
    errors = 0
    for env in ('LOCALAPPDATA', 'APPDATA', 'NPM_CONFIG_CACHE'):
        if not os.environ.get(env):
            continue
        cache = Path(os.environ[env]) / ('_npx' if env == 'NPM_CONFIG_CACHE' else 'npm-cache/_npx')
        try:
            if cache.is_dir() and not _redirected(cache):
                for i, child in enumerate(cache.iterdir()):
                    if i >= MAX_PACKAGES:
                        errors += 1
                        break
                    if not _redirected(child):
                        roots.append(child / 'node_modules')
        except OSError:
            errors += 1
    # Only immediate C:\dev projects: no recursive walk of wallets or arbitrary files.
    repo_manifests = []
    dev_root = Path('C:/dev')
    try:
        if dev_root.is_dir() and not _redirected(dev_root):
            for i, child in enumerate(dev_root.iterdir()):
                if i >= MAX_PACKAGES:
                    errors += 1
                    break
                if child.is_dir() and not _redirected(child) and (child / 'package.json').is_file():
                    repo_manifests.append(child / 'package.json')
    except OSError:
        errors += 1
    packages, package_errors = collect_packages(roots, repo_manifests=repo_manifests)
    entries, run_errors = read_run_entries()
    findings = assess(packages, entries, allowlist)
    if errors + package_errors + run_errors:
        findings.append(Finding('low', 'supply-chain', 'Supply-chain coverage incomplete',
            'Some metadata or startup entries were unreadable, malformed or exceeded scan limits. '
            'Known false positives: permission restrictions and interrupted installs.',
            fix='Review package directory permissions and incomplete installs, then scan again.',
            data={'unavailable': errors + package_errors + run_errors}))
    return findings
