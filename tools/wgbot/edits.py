"""Parse a model's SEARCH/REPLACE edits, apply them to allowed files only, and refuse dangerous code.

The bot runs the test suite on the model's code, so model output executes on this PC. Edits
are therefore limited to the files the issue names, and any added line that reaches for the
network, processes, the registry, raw memory or dynamic code is refused before tests run.
External mesh nodes are untrusted: this check is what keeps a bad node from running code here.
"""

import os
import re

BLOCK = re.compile(
    r"FILE:\s*(?P<path>[^\n]+?)\s*\n<<<<<<< SEARCH\n(?P<search>.*?)\n?=======\n(?P<replace>.*?)\n?>>>>>>> REPLACE",
    re.S,
)

# Added code may not introduce these. The owner can allow them per issue with the
# `bot-allow-system` label when a task genuinely needs one.
DANGEROUS = [
    (re.compile(r"\b(import|from)\s+(subprocess|socket|urllib|http|requests|ctypes|winreg|shutil|"
                r"multiprocessing|pickle|marshal|asyncio\.subprocess|ftplib|smtplib|telnetlib)\b"),
     "imports a network/process/registry/raw-memory module"),
    (re.compile(r"\b(os\.(system|popen|remove|unlink|rmdir|removedirs|rename|replace|startfile|exec\w*|spawn\w*|kill)"
                r"|eval|exec|compile|__import__|getattr\s*\(\s*__builtins__)\s*\("), "runs or deletes things"),
    (re.compile(r"\bopen\s*\([^)]*['\"][wax+]"), "writes files"),
    (re.compile(r"\b(Popen|check_output|check_call|urlopen)\s*\("), "starts processes or opens URLs"),
]


class EditError(ValueError):
    """The model's reply couldn't be applied safely; the message goes back to the model."""


def parse(reply):
    edits = [(m["path"].strip().strip("`"), m["search"], m["replace"]) for m in BLOCK.finditer(reply)]
    if not edits:
        raise EditError("no edits found. Reply with FILE:/SEARCH/REPLACE blocks exactly as shown.")
    return edits


def unsafe_lines(added_text):
    hits = []
    for line in added_text.splitlines():
        code = line.split("#", 1)[0]
        for pat, why in DANGEROUS:
            if pat.search(code):
                hits.append(f"{line.strip()[:80]!r}: {why}")
    return hits


def apply(root, edits, allowed, allow_system=False):
    """Apply edits under root to the allowed relative paths. All or nothing. Returns changed paths."""
    allowed = {a.replace("\\", "/") for a in allowed}
    new_text, problems = {}, []
    for path, search, replace in edits:
        rel = path.replace("\\", "/").lstrip("./")
        if rel not in allowed:
            problems.append(f"{rel}: not one of the files this issue allows ({', '.join(sorted(allowed))})")
            continue
        full = os.path.join(root, rel)
        current = new_text.get(rel)
        if current is None:
            current = ""
            if os.path.exists(full):
                with open(full, encoding="utf-8") as fh:
                    current = fh.read()
        if search == "":
            if current:
                problems.append(f"{rel}: empty SEARCH is only for creating a new file")
                continue
            updated = replace + ("\n" if replace and not replace.endswith("\n") else "")
        else:
            count = current.count(search)
            if count != 1:
                problems.append(f"{rel}: SEARCH text found {count} times; it must match exactly once "
                                "(copy it character for character, including indentation)")
                continue
            updated = current.replace(search, replace, 1)
        if not allow_system:
            added = "\n".join(set(replace.splitlines()) - set(search.splitlines()))
            for hit in unsafe_lines(added):
                problems.append(f"{rel}: refused {hit}")
        new_text[rel] = updated
    if problems:
        raise EditError("\n".join(problems))
    for rel, text in new_text.items():
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return sorted(new_text)
