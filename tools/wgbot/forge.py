"""wgbot: a local-AI model proposes a fix for one labelled WalletGuard issue; the tests decide.

    python -m tools.wgbot.forge --once            work the oldest eligible issue, then exit
    python -m tools.wgbot.forge --issue 12        work one specific issue
    python -m tools.wgbot.forge --once --dry-run  everything except push / PR / issue comments

An issue is a bot task only if the owner gives it the `bot-task` label (only collaborators can
label, so the owner picks every task) and its body says what to change and how to check it:

    Files: walletguard/addresses.py
    Test:
    ```python
    import unittest
    ...
    ```

Each run, in order:
1. Stops if the kill switch file exists (%LOCALAPPDATA%\\WalletGuardBot\\STOP).
2. Resets its own git worktree (never your checkout) to origin/main, writes the issue's test as
   tests/test_issue_<n>.py, and checks it FAILS there. No failing test, nothing to verify against.
3. Asks the model (via the node pool: this PC, LAN or Tailscale) for SEARCH/REPLACE edits to the
   listed files only. Edits that add network, process, registry or file-deleting code are refused.
4. Runs the whole test suite. Failures go back to the model, up to --attempts times.
5. If everything passes: pushes branch bot/issue-<n> and opens a DRAFT pull request with the
   evidence. CI runs on it. A human reviews and merges; the bot never merges or touches main.
   Otherwise it comments once on the issue with what went wrong and labels it `bot-gave-up`.
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile

from . import edits, nodes

LABEL = "bot-task"
SKIP_LABELS = {"no-bot", "bot-gave-up", "bot-pr-open"}
ALLOW_SYSTEM_LABEL = "bot-allow-system"
FILES_ALLOWED = re.compile(r"^walletguard/[A-Za-z0-9_/]+\.py$")
MAX_FILES = 3
DEFAULT_MODEL = os.environ.get("WGBOT_MODEL", "qwen3.6:35b")
REPO = os.environ.get("WGBOT_REPO", "sapperskills/walletguard")
MAIN_REPO = os.environ.get("WGBOT_MAIN_CHECKOUT", os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()), "WalletGuardBot")
WORKTREE = os.environ.get("WGBOT_WORKTREE", r"C:\dev\WalletGuard-bot")
STOP_FILE = os.path.join(DATA_DIR, "STOP")
STATE_FILE = os.path.join(DATA_DIR, "state.json")

SYSTEM = """You fix one GitHub issue in WalletGuard, a Python standard-library-only Windows tool that
protects crypto wallets. Rules: change only the files you are given; no third-party packages; never
add code that uses the network, starts processes, edits the registry or deletes files; keep the
surrounding style. Make the failing test pass without breaking other tests. Do not edit tests.

Reply ONLY with one or more edit blocks in exactly this format (SEARCH must match the file exactly
once, including indentation):

FILE: walletguard/example.py
<<<<<<< SEARCH
old lines
=======
new lines
>>>>>>> REPLACE
"""


class TaskRefused(ValueError):
    """The issue isn't a valid bot task."""


# ---------------------------------------------------------------- pure helpers (unit-tested)

def parse_task(body):
    """Return (files, test_code) from an issue body, or raise TaskRefused."""
    body = (body or "").replace("\r\n", "\n")
    m = re.search(r"^Files:\s*(.+)$", body, re.M)
    if not m:
        raise TaskRefused("the issue body needs a 'Files:' line")
    files = [f.strip().strip("`") for f in m.group(1).split(",") if f.strip()]
    if not files or len(files) > MAX_FILES:
        raise TaskRefused(f"'Files:' must list 1 to {MAX_FILES} files")
    bad = [f for f in files if not FILES_ALLOWED.match(f) or ".." in f]
    if bad:
        raise TaskRefused(f"only walletguard/*.py files may be changed, not {bad}")
    t = re.search(r"^Test:\s*\n```(?:python)?\n(.*?)\n```", body, re.M | re.S)
    if not t or "unittest" not in t.group(1):
        raise TaskRefused("the issue body needs a 'Test:' section with a ```python unittest block")
    return files, t.group(1) + "\n"


def eligible(issue):
    labels = {lab["name"] for lab in issue.get("labels", [])}
    return LABEL in labels and not labels & SKIP_LABELS


def build_prompt(issue, files_text, test_code, feedback=None):
    parts = [f"Issue #{issue['number']}: {issue['title']}\n\n{issue.get('body', '')}\n"]
    for path, text in files_text.items():
        parts.append(f"--- {path} ---\n{text}")
    parts.append(f"--- tests/test_issue_{issue['number']}.py (must pass; do not edit) ---\n{test_code}")
    if feedback:
        parts.append(f"Your previous attempt did not work:\n{feedback}\nFix it and reply with edit blocks only.")
    else:
        parts.append("Reply with edit blocks only.")
    return "\n\n".join(parts)


def tail(text, n=3000):
    return text if len(text) <= n else "…" + text[-n:]


# ---------------------------------------------------------------- side effects

def sh(args, cwd=None, timeout=600, check=True):
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:3])}…: {p.stderr.strip() or p.stdout.strip()}"[:600])
    return p


def gh_json(args):
    return json.loads(sh(["gh"] + args, cwd=MAIN_REPO).stdout or "null")


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=1)


def prepare_worktree():
    sh(["git", "fetch", "-q", "origin", "main"], cwd=MAIN_REPO)
    if not os.path.isdir(os.path.join(WORKTREE, ".git")) and not os.path.isfile(os.path.join(WORKTREE, ".git")):
        sh(["git", "worktree", "add", "--detach", WORKTREE, "origin/main"], cwd=MAIN_REPO)
    sh(["git", "checkout", "-q", "--detach", "origin/main"], cwd=WORKTREE)
    sh(["git", "reset", "-q", "--hard", "origin/main"], cwd=WORKTREE)
    sh(["git", "clean", "-qfdx"], cwd=WORKTREE)  # the bot's own worktree only
    return sh(["git", "rev-parse", "HEAD"], cwd=WORKTREE).stdout.strip()


def run_tests(test_path=None):
    args = [sys.executable, "-m", "unittest"] + ([test_path] if test_path else ["discover", "-s", "tests"])
    p = sh(args, cwd=WORKTREE, timeout=600, check=False)
    return p.returncode == 0, p.stdout + p.stderr


def work(issue, pool, attempts, dry_run):
    n = issue["number"]
    files, test_code = parse_task(issue.get("body"))
    allow_system = ALLOW_SYSTEM_LABEL in {lab["name"] for lab in issue.get("labels", [])}
    base = prepare_worktree()
    test_rel = f"tests/test_issue_{n}.py"
    with open(os.path.join(WORKTREE, test_rel), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(test_code)
    ok, out = run_tests(f"tests.test_issue_{n}")
    if ok:
        return {"outcome": "refused", "reason": "the issue's test already passes on main: nothing to fix",
                "base": base}

    files_text = {}
    for f in files:
        full = os.path.join(WORKTREE, f)
        files_text[f] = "(new file)"
        if os.path.exists(full):
            with open(full, encoding="utf-8") as fh:
                files_text[f] = fh.read()
    history, feedback = [], None
    for attempt in range(1, attempts + 1):
        prompt = build_prompt(issue, files_text, test_code, feedback)
        try:
            reply = pool.chat([{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
                              temperature=0.0 if attempt == 1 else 0.7, seed=attempt)
        except nodes.NoNodeAvailable as e:
            return {"outcome": "error", "reason": str(e), "base": base, "history": history}
        step = {"attempt": attempt, "node": pool.last_node}
        sh(["git", "checkout", "-q", "--"] + [f for f in files if files_text[f] != "(new file)"], cwd=WORKTREE,
           check=False)
        try:
            changed = edits.apply(WORKTREE, edits.parse(reply), files, allow_system)
        except (edits.EditError, OSError) as e:
            feedback = f"Your edits could not be applied:\n{e}"
            history.append({**step, "result": "edit refused", "detail": str(e)[:500]})
            continue
        ok, out = run_tests()
        if ok:
            history.append({**step, "result": "all tests pass", "changed": changed})
            return {"outcome": "fixed", "base": base, "history": history, "changed": changed,
                    "test_output": tail(out, 1500), "test_rel": test_rel}
        feedback = f"The tests failed:\n{tail(out)}"
        history.append({**step, "result": "tests fail", "detail": tail(out, 800)})
    return {"outcome": "gave-up", "reason": f"no passing fix in {attempts} attempts", "base": base,
            "history": history}


def pr_body(issue, rep, model):
    lines = [f"Proposed by **wgbot** ({model}, local mesh) for #{issue['number']}. **Draft: needs human review.**", "",
             "**Evidence (VERIFIED):** the issue's test failed on `main` and the full suite passes with this change:",
             "```", rep["test_output"].strip(), "```", "",
             "**Weakest claim (ASSUMED):** the test in the issue fully captures the intended behaviour; review the diff, "
             "not just the green tick.", "", f"Base: `{rep['base'][:9]}` · Files: {', '.join(rep['changed'])} · "
             f"Test added: `{rep['test_rel']}`", "", "| Attempt | Node | Result |", "|---|---|---|"]
    for h in rep["history"]:
        node = h.get("node") or {}
        lines.append(f"| {h['attempt']} | {node.get('name', '?')} ({node.get('seconds', '?')}s) | {h['result']} |")
    lines += ["", f"Closes #{issue['number']}"]
    return "\n".join(lines)


def publish(issue, rep, model, dry_run):
    n = issue["number"]
    if rep["outcome"] == "fixed":
        branch = f"bot/issue-{n}"
        sh(["git", "checkout", "-q", "-B", branch], cwd=WORKTREE)
        sh(["git", "add", "--"] + rep["changed"] + [rep["test_rel"]], cwd=WORKTREE)
        sh(["git", "-c", "user.name=wgbot", "-c", "user.email=wgbot@users.noreply.github.com", "commit", "-q", "-m",
            f"Fix #{n}: {issue['title']}\n\nProposed by wgbot ({model}); the issue's test failed before and the "
            "full suite passes after."], cwd=WORKTREE)
        if dry_run:
            return f"dry run: committed locally on {branch}"
        sh(["git", "push", "-q", "-f", "origin", f"{branch}:refs/heads/{branch}"], cwd=WORKTREE)
        body = pr_body(issue, rep, model)
        url = sh(["gh", "pr", "create", "--repo", REPO, "--draft", "--base", "main", "--head", branch,
                  "--title", f"Bot: {issue['title']} (#{n})", "--body", body], cwd=WORKTREE).stdout.strip()
        sh(["gh", "issue", "edit", str(n), "--repo", REPO, "--add-label", "bot-pr-open"], cwd=MAIN_REPO)
        return url
    if dry_run:
        return f"dry run: would comment '{rep['outcome']}' on #{n}"
    detail = "\n".join(f"- attempt {h['attempt']}: {h['result']}" for h in rep.get("history", []))
    sh(["gh", "issue", "comment", str(n), "--repo", REPO, "--body",
        f"wgbot ({model}) could not fix this: **{rep['outcome']}**: {rep.get('reason', '')}\n\n{detail}\n\n"
        "A human can take it, or adjust the issue's Files/Test and remove the `bot-gave-up` label to retry."],
       cwd=MAIN_REPO)
    if rep["outcome"] in ("gave-up", "refused"):
        sh(["gh", "issue", "edit", str(n), "--repo", REPO, "--add-label", "bot-gave-up"], cwd=MAIN_REPO)
    return "commented"


def write_report(issue, rep, result):
    os.makedirs(os.path.join(DATA_DIR, "reports"), exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(DATA_DIR, "reports", f"issue-{issue['number']}-{stamp}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"issue": issue["number"], "title": issue["title"], **rep, "result": result}, fh, indent=1)
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wgbot")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--once", action="store_true", help="work the oldest eligible issue")
    g.add_argument("--issue", type=int)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--dry-run", action="store_true", help="no push, PR, comments or labels")
    a = ap.parse_args(argv)

    if os.path.exists(STOP_FILE):
        print(f"kill switch engaged ({STOP_FILE}); remove it to run")
        return 0
    fields = ["--json", "number,title,body,labels,updatedAt"]
    if a.issue:
        issue = gh_json(["issue", "view", str(a.issue), "--repo", REPO] + fields)
    else:
        issues = gh_json(["issue", "list", "--repo", REPO, "--state", "open", "--label", LABEL, "--limit", "50"] + fields)
        state = load_state()
        todo = [i for i in sorted(issues or [], key=lambda i: i["number"])
                if eligible(i) and state.get(str(i["number"])) != i["updatedAt"]]
        if not todo:
            print("no eligible bot-task issues")
            return 0
        issue = todo[0]
    pool = nodes.Pool(nodes.pool_from_env(), a.model)
    print(f"#{issue['number']} {issue['title']} — model {a.model}, nodes {[n.name for n in pool.nodes]}", flush=True)
    try:
        rep = work(issue, pool, a.attempts, a.dry_run)
    except TaskRefused as e:
        rep = {"outcome": "refused", "reason": str(e), "base": None}
    result = publish(issue, rep, a.model, a.dry_run) if rep["outcome"] != "error" else rep["reason"]
    print(f"{rep['outcome']}: {result}\nreport: {write_report(issue, rep, result)}")
    if not a.dry_run:
        state = load_state()
        state[str(issue["number"])] = issue["updatedAt"]
        save_state(state)
    return 0 if rep["outcome"] in ("fixed", "refused", "gave-up") else 1


if __name__ == "__main__":
    sys.exit(main())
