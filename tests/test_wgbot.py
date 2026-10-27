"""The local-AI issue bot: task parsing, safe edit application, node pool failover."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.wgbot import edits, forge, nodes

BODY = """Recognise testnet addresses.

Files: walletguard/addresses.py
Test:
```python
import unittest
class T(unittest.TestCase):
    def test_x(self):
        self.assertTrue(True)
```
"""


def block(path, search, replace):
    return f"FILE: {path}\n<<<<<<< SEARCH\n{search}\n=======\n{replace}\n>>>>>>> REPLACE\n"


class Task(unittest.TestCase):
    def test_parse(self):
        files, test = forge.parse_task(BODY)
        self.assertEqual(files, ["walletguard/addresses.py"])
        self.assertIn("class T", test)

    def test_refusals(self):
        for body in ("no files line", BODY.replace("walletguard/addresses.py", "tests/test_core.py"),
                     BODY.replace("walletguard/addresses.py", "walletguard/../x.py"),
                     BODY.split("Test:")[0], "Files: " + ",".join(f"walletguard/m{i}.py" for i in range(4)) + "\n"):
            with self.assertRaises(forge.TaskRefused):
                forge.parse_task(body)

    def test_eligible(self):
        lab = lambda *n: [{"name": x} for x in n]
        self.assertTrue(forge.eligible({"labels": lab("bot-task", "good first issue")}))
        self.assertFalse(forge.eligible({"labels": lab("good first issue")}))
        for skip in ("no-bot", "bot-gave-up", "bot-pr-open"):
            self.assertFalse(forge.eligible({"labels": lab("bot-task", skip)}))


class Edits(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.makedirs(os.path.join(self.tmp.name, "walletguard"))
        with open(os.path.join(self.tmp.name, "walletguard", "a.py"), "w") as fh:
            fh.write("X = 1\nY = 2\n")
        self.allowed = ["walletguard/a.py"]

    def tearDown(self):
        self.tmp.cleanup()

    def read(self):
        with open(os.path.join(self.tmp.name, "walletguard", "a.py")) as fh:
            return fh.read()

    def test_apply(self):
        edits.apply(self.tmp.name, edits.parse(block("walletguard/a.py", "Y = 2", "Y = 3")), self.allowed)
        self.assertEqual(self.read(), "X = 1\nY = 3\n")

    def test_other_files_refused(self):
        with self.assertRaises(edits.EditError):
            edits.apply(self.tmp.name, edits.parse(block("tests/test_core.py", "a", "b")), self.allowed)

    def test_ambiguous_or_missing_search_refused_and_nothing_written(self):
        reply = block("walletguard/a.py", "Y = 2", "Y = 3") + block("walletguard/a.py", "Z = 9", "Z = 0")
        with self.assertRaises(edits.EditError):
            edits.apply(self.tmp.name, edits.parse(reply), self.allowed)
        self.assertEqual(self.read(), "X = 1\nY = 2\n")  # all or nothing

    def test_dangerous_code_refused(self):
        for bad in ("import subprocess", "from urllib import request", "os.system('x')", "eval(s)",
                    "open(p, 'w')", "x = __import__('socket')", "import ctypes", "os.remove(p)"):
            with self.assertRaises(edits.EditError, msg=bad):
                edits.apply(self.tmp.name, edits.parse(block("walletguard/a.py", "Y = 2", f"Y = 2\n{bad}")),
                            self.allowed)
        self.assertEqual(self.read(), "X = 1\nY = 2\n")

    def test_owner_label_allows_system_code(self):
        edits.apply(self.tmp.name, edits.parse(block("walletguard/a.py", "Y = 2", "import subprocess")),
                    self.allowed, allow_system=True)
        self.assertIn("subprocess", self.read())

    def test_existing_dangerous_lines_kept_are_fine(self):
        with open(os.path.join(self.tmp.name, "walletguard", "a.py"), "w") as fh:
            fh.write("import subprocess\nY = 2\n")
        edits.apply(self.tmp.name, edits.parse(block("walletguard/a.py", "import subprocess\nY = 2",
                                                     "import subprocess\nY = 3")), self.allowed)
        self.assertIn("Y = 3", self.read())

    def test_no_blocks(self):
        with self.assertRaises(edits.EditError):
            edits.parse("Sure! Here is the fix: change Y to 3.")


class Nodes(unittest.TestCase):
    def test_only_private_addresses(self):
        for ok in ("http://127.0.0.1:11434", "http://192.168.1.20:11434", "http://100.101.102.103:11434",
                   "http://box.tail1234.ts.net:11434"):
            nodes.check_url(ok)
        for bad in ("http://8.8.8.8:11434", "http://127.0.0.1", "http://u:p@127.0.0.1:11434",
                    "http://127.0.0.1:11434/api", "ftp://127.0.0.1:21"):
            with self.assertRaises(nodes.NodeRefused, msg=bad):
                nodes.check_url(bad)

    def test_parse_nodes(self):
        got = nodes.parse_nodes("local=http://127.0.0.1:11434, den=http://100.64.0.5:11434")
        self.assertEqual([n.name for n in got], ["local", "den"])
        with self.assertRaises(nodes.NodeRefused):
            nodes.parse_nodes("http://127.0.0.1:11434")

    def test_failover_and_model_check(self):
        pool_nodes = [nodes.Node("down", "http://127.0.0.1:1"), nodes.Node("nomodel", "http://127.0.0.1:2"),
                      nodes.Node("flaky", "http://127.0.0.1:3"), nodes.Node("good", "http://127.0.0.1:4")]
        tags = {"down": None, "nomodel": {"llama3:latest"}, "flaky": {"qwen3:8b"}, "good": {"qwen3:8b"}}

        def chat(node, *a):
            if node.name == "flaky":
                raise OSError("connection reset")
            return f"answer from {node.name}"

        p = nodes.Pool(pool_nodes, "qwen3:8b", chat_fn=chat, tags_fn=lambda n: tags[n.name])
        self.assertEqual(p.chat([{"role": "user", "content": "hi"}]), "answer from good")
        self.assertEqual(p.last_node["name"], "good")
        with self.assertRaises(nodes.NoNodeAvailable):
            nodes.Pool(pool_nodes, "missing:1b", chat_fn=chat, tags_fn=lambda n: tags[n.name]).chat([])


if __name__ == "__main__":
    unittest.main()
