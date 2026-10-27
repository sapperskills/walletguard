# Writing a detector

A detector finds one way crypto gets stolen and tells the user, in plain English, what to do.
The worked example is [`walletguard/clipboard_history.py`](../walletguard/clipboard_history.py)
(Windows clipboard history keeps copied seed phrases) with its tests in
[`tests/test_clipboard_history.py`](../tests/test_clipboard_history.py). Copy that shape.

## The shape: collect, assess, check

```python
def read_settings():          # 1. collector: read Windows state, nothing else
    ...                       #    registry, files, PowerShell; return plain data (dict/list)

def assess(settings):         # 2. pure logic: data -> list[Finding]; no I/O, so it's easy to test
    if settings.get("EnableClipboardHistory") == 1:
        return [Finding("low", "clipboard", "Clipboard history is on",
                        "Windows keeps the last 25 things you copied ...",
                        fix="Press Win+V → Clear all ...")]
    return []

def check():                  # 3. glue, registered in walletguard/scanner.py CHECKS
    return assess(read_settings())
```

Then add one line to `CHECKS` in [`walletguard/scanner.py`](../walletguard/scanner.py). Both
`python -m walletguard scan` and the tray pick it up.

## A good `Finding`

`Finding(severity, category, title, detail, fix, data)`

| Field | Rule |
|---|---|
| `severity` | `critical`: funds are at risk right now (patched wallet, clipper caught). `high`: an active attack path next to a wallet. `medium`: a real weakness. `low`: hygiene. `info`: context only. |
| `title` | What was found, short. Name the thing (extension, task, file). |
| `detail` | Why it matters for crypto, in one or two sentences a non-programmer understands. |
| `fix` | What to click or run. Never "contact support". |
| `data` | Paths/IDs for the JSON report. **Never secrets.** |

## Tests

Test `assess()` with made-up input: the clean case returns nothing, each risky case returns the
right severity, and borderline cases don't over-alert. Simulate attacks harmlessly: fake extension
folders in a temp dir, synthetic addresses built with the format's own checksum. Never real
malware, seeds or funds.

```
python -m unittest discover -s tests -v
```

## Checklist before you open a pull request

- Read-only. Anything that changes the PC is opt-in, reversible and logged.
- Standard library only, original code.
- Your known false positives are listed in the PR (developer tools must not rate high on one weak signal).
- No secrets are read, logged or put in `data`.

## Want the bot to do it?

Small, well-specified changes can go to **wgbot**, the local-AI issue bot: see [BOT.md](BOT.md).
