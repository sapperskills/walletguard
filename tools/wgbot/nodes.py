"""A pool of Ollama nodes (this PC, LAN, Tailscale) with failover.

This is CutShit Neural Mesh Mode A applied to WalletGuard: each request is answered whole by
one node, so nothing crosses the network mid-generation. Nodes are reachable only on loopback,
private LAN or Tailscale, because Ollama has no authentication; a public address is refused.

    WGBOT_NODES="local=http://127.0.0.1:11434,den=http://100.101.102.103:11434"
"""

import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

TAILSCALE = ipaddress.ip_network("100.64.0.0/10")
DEFAULT_NODES = "local=http://127.0.0.1:11434"


class NodeRefused(ValueError):
    """A node address outside loopback, private LAN and Tailscale."""


class NoNodeAvailable(RuntimeError):
    """No node in the pool could answer."""


@dataclass
class Node:
    name: str
    url: str


def _allowed_ip(ip):
    return ip.is_loopback or ip.is_private or (ip.version == 4 and ip in TAILSCALE)


def check_url(url, resolve=socket.getaddrinfo):
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname or not u.port:
        raise NodeRefused(f"{url!r}: needs http(s)://host:port")
    if u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
        raise NodeRefused(f"{url!r}: no credentials, path, query or fragment")
    host = u.hostname
    if host.endswith(".ts.net"):
        return url.rstrip("/")
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            ips = [ipaddress.ip_address(a[4][0]) for a in resolve(host, None)]
        except OSError as e:
            raise NodeRefused(f"{url!r}: cannot resolve {host}") from e
    if not ips or not all(_allowed_ip(ip) for ip in ips):
        raise NodeRefused(f"{url!r}: only loopback, private LAN or Tailscale nodes (Ollama has no auth)")
    return url.rstrip("/")


def parse_nodes(spec):
    nodes = []
    for part in (spec or "").split(","):
        if not part.strip():
            continue
        name, sep, url = part.partition("=")
        if not sep:
            raise NodeRefused(f"{part!r}: expected name=http://host:port")
        nodes.append(Node(name.strip(), check_url(url.strip())))
    return nodes


def pool_from_env():
    return parse_nodes(os.environ.get("WGBOT_NODES", DEFAULT_NODES))


def _post(url, body, timeout):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def models_on(node, timeout=5):
    try:
        with urllib.request.urlopen(f"{node.url}/api/tags", timeout=timeout) as r:
            return {m["name"] for m in json.loads(r.read().decode()).get("models", [])}
    except (OSError, ValueError, urllib.error.URLError):
        return None  # node down


def has_model(available, model):
    return model in available or (":" not in model and f"{model}:latest" in available)


class Pool:
    """Pick the first node that is up and has the model; on failure move to the next one."""

    def __init__(self, nodes, model, chat_fn=None, tags_fn=None):
        self.nodes = list(nodes)
        self.model = model
        self._chat = chat_fn or self._ollama_chat
        self._tags = tags_fn or models_on
        self.last_node = None

    def _ollama_chat(self, node, messages, temperature, seed, num_ctx, timeout):
        body = {"model": self.model, "messages": messages, "stream": False,
                "options": {"temperature": temperature, "seed": seed, "num_ctx": num_ctx}}
        return _post(f"{node.url}/api/chat", body, timeout)["message"]["content"]

    def ready_nodes(self):
        out = []
        for n in self.nodes:
            tags = self._tags(n)
            if tags is not None and has_model(tags, self.model):
                out.append(n)
        return out

    def chat(self, messages, temperature=0.0, seed=0, num_ctx=32768, timeout=3600):
        errors = []
        for n in self.ready_nodes():
            t0 = time.monotonic()
            try:
                reply = self._chat(n, messages, temperature, seed, num_ctx, timeout)
            except (OSError, ValueError, KeyError, urllib.error.URLError) as e:
                errors.append(f"{n.name}: {e!r}")
                continue
            self.last_node = {"name": n.name, "seconds": round(time.monotonic() - t0, 1)}
            return reply
        raise NoNodeAvailable(f"no node could run {self.model}: " + ("; ".join(errors) or "none up with that model"))
