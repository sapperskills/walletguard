# wgbot: the local-AI issue bot

wgbot works small WalletGuard issues with **local AI**, Ollama on the owner's PC or on other
opted-in machines over LAN/Tailscale (CutShit Neural Mesh, Mode A). No cloud AI, no API keys,
nothing private sent anywhere: the code and issues are already public.

**The tests decide, a human merges.** The bot only opens *draft* pull requests, CI runs on them,
and a maintainer reviews and merges. The bot never merges and never pushes to `main`.

## Giving the bot a task

Only maintainers can label issues, so the owner picks every bot task:

1. Write the issue with a `Files:` line and a failing `Test:` (or use the **Bot task** issue template):

   ````
   Files: walletguard/addresses.py
   Test:
   ```python
   import unittest
   from walletguard import addresses

   class T(unittest.TestCase):
       def test_testnet(self):
           self.assertEqual(addresses.classify("tb1q..."), "BTC testnet")
   ```
   ````
2. Add the `bot-task` label.

The bot writes the test as `tests/test_issue_<n>.py`, checks it **fails** on `main` (otherwise
there's nothing to verify), asks the model for edits to the listed files only, and runs the
**whole** suite. Failures go back to the model (3 attempts by default). If everything passes it
opens a draft PR; if not, it comments once and labels the issue `bot-gave-up`.

| Label | Meaning |
|---|---|
| `bot-task` | The bot may work this issue |
| `bot-pr-open` | The bot opened a draft PR for it |
| `bot-gave-up` | No passing fix; remove the label to let it retry |
| `no-bot` | Never touch this issue |
| `bot-allow-system` | Owner allows network/process/registry code in this task (off by default) |

Good bot tasks are small and fully described by one test: a new address format, a new known
wallet ID, a tweak to one detector's severity. Big features stay with humans.

## Safety

- Model output runs on the bot's PC when the tests run, so edits are limited to 1–3 listed
  `walletguard/*.py` files, can't touch tests, and any **added** line that imports network,
  process, registry or raw-memory modules, deletes files, writes files or uses `eval`/`exec` is
  refused before anything runs. Mesh nodes are treated as untrusted.
- Nodes must be on loopback, private LAN or Tailscale (Ollama has no authentication).
- The bot works in its own git worktree (`C:\dev\WalletGuard-bot`), never in your checkout.
- Kill switch: create `%LOCALAPPDATA%\WalletGuardBot\STOP`. Reports: `%LOCALAPPDATA%\WalletGuardBot\reports`.

## Running it

```
python -m tools.wgbot.forge --once --dry-run   # try it: no push, PR or comments
python -m tools.wgbot.forge --once             # work the oldest bot-task issue
python -m tools.wgbot.forge --issue 12         # one specific issue
```

| Setting | Default |
|---|---|
| `WGBOT_MODEL` / `--model` | `qwen3.6:35b` |
| `WGBOT_NODES` | `local=http://127.0.0.1:11434`; add mesh nodes: `local=...,den=http://100.x.y.z:11434` |
| `WGBOT_WORKTREE` | `C:\dev\WalletGuard-bot` |

Needs `git` and an authenticated `gh` on the PC that runs it.

### Every hour, automatically

`tools\wgbot\run-wgbot.cmd` runs one pass and logs to `%LOCALAPPDATA%\WalletGuardBot\wgbot.log`.
Register it once from **your own** PowerShell (not from inside an AI agent's sandbox):

```
schtasks /create /tn "WalletGuard Bot" /tr "C:\dev\WalletGuard\tools\wgbot\run-wgbot.cmd" /sc hourly /f
```

Stop: `schtasks /delete /tn "WalletGuard Bot" /f`, or create the STOP file.

## Adding compute (the mesh)

Any PC with Ollama and the model can join: install Tailscale on both machines, run Ollama on
the other PC with `OLLAMA_HOST=0.0.0.0`, pull the model, and add it to `WGBOT_NODES`. The bot
uses the first node that's up and has the model, and moves to the next if one fails. Only add
machines you trust: what they return is checked by the safety rules and the tests, but still
runs on the bot's PC.
