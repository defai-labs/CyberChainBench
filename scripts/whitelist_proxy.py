#!/usr/bin/env python3
"""Lightweight HTTP/HTTPS whitelist proxy.

Runs on localhost:18080 inside the container. Only forwards requests to
whitelisted domains; all others get 403. Supports CONNECT (for HTTPS).

Usage:
    python3 /usr/local/bin/whitelist_proxy.py &
    export HTTP_PROXY=http://127.0.0.1:18080
    export HTTPS_PROXY=http://127.0.0.1:18080
"""
import http.server
import re
import socket
import socketserver
import select
import threading
import urllib.parse
import sys
import os

LISTEN_PORT = int(os.environ.get("PROXY_PORT", "18080"))

ALLOWED_DOMAINS = [
    # Block explorers (Etherscan family)
    "etherscan.io",
    "bscscan.com",
    "polygonscan.com",
    "arbiscan.io",
    "basescan.org",
    "snowtrace.io",
    "ftmscan.com",
    "gnosisscan.io",
    "blastscan.io",
    "mantlescan.xyz",
    "lineascan.build",
    # RPC providers
    "alchemy.com",
    "infura.io",
    "quicknode.com",
    # LLM APIs
    "anthropic.com",            # Claude (api.anthropic.com)
    "openai.com",               # OpenAI / GPT (api.openai.com)
    "azure.com",                # Azure OpenAI (*.openai.azure.com)
    "googleapis.com",           # Google Gemini (generativelanguage.googleapis.com, Vertex AI)
    "google.com",               # Google AI / Vertex auth
    "x.ai",                     # xAI Grok (api.x.ai)
    "deepseek.com",             # DeepSeek (api.deepseek.com)
    "mistral.ai",               # Mistral (api.mistral.ai)
    "cohere.com",               # Cohere (api.cohere.com)
    "cohere.ai",
    "groq.com",                 # Groq (api.groq.com)
    "together.ai",              # Together AI (api.together.xyz)
    "together.xyz",
    "fireworks.ai",             # Fireworks (api.fireworks.ai)
    "openrouter.ai",            # OpenRouter aggregator (openrouter.ai)
    "perplexity.ai",            # Perplexity (api.perplexity.ai)
    "bigmodel.cn",              # Zhipu GLM (open.bigmodel.cn)
    "moonshot.cn",              # Moonshot Kimi (api.moonshot.cn)
    "dashscope.aliyuncs.com",   # Alibaba Qwen / DashScope
    # System packages (apt, npm, pip, uv for agent install)
    "deb.debian.org",
    "security.debian.org",
    "registry.npmjs.org",
    "npmjs.org",
    "github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "astral.sh",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    # Localhost (MCP tools)
    "localhost",
    "127.0.0.1",
]


def is_allowed(hostname: str) -> bool:
    hostname = hostname.lower().split(":")[0]
    for domain in ALLOWED_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False


def allowed_connect_target(authority: str) -> tuple[str, int] | None:
    """Parse a hostname authority and apply the CONNECT destination policy."""
    match = re.fullmatch(r"([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)(?::([0-9]+))?", authority)
    if match is None:
        return None
    host, port_text = match.groups()
    if len(host) > 253 or any(
        len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in host.split(".")
    ):
        return None
    try:
        port = int(port_text) if port_text is not None else 443
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    host = host.lower()
    # The pinned decompiler needs only this exact HTTPS authority, not subdomains.
    if is_allowed(host) or (host == "ethervm.io" and port_text == "443"):
        return host, port
    return None


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    timeout = 30

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunneling."""
        target = allowed_connect_target(self.path)
        if target is None:
            self.send_error(403, "Blocked: CONNECT destination not in whitelist")
            return

        host, port = target
        try:
            remote = socket.create_connection((host, port), timeout=10)
        except Exception as e:
            self.send_error(502, f"Cannot connect to {self.path}: {e}")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        # Tunnel data between client and remote
        conns = [self.connection, remote]
        keep_going = True
        while keep_going:
            readable, _, errored = select.select(conns, [], conns, 30)
            if errored:
                break
            for sock in readable:
                data = sock.recv(65536)
                if not data:
                    keep_going = False
                    break
                other = remote if sock is self.connection else self.connection
                other.sendall(data)
        remote.close()

    def do_GET(self):
        self._proxy_request()

    def do_POST(self):
        self._proxy_request()

    def do_PUT(self):
        self._proxy_request()

    def do_DELETE(self):
        self._proxy_request()

    def do_PATCH(self):
        self._proxy_request()

    def do_HEAD(self):
        self._proxy_request()

    def do_OPTIONS(self):
        self._proxy_request()

    def _proxy_request(self):
        """Forward HTTP requests (non-CONNECT)."""
        parsed = urllib.parse.urlparse(self.path)
        host = parsed.hostname or ""

        if not is_allowed(host):
            self.send_error(403, f"Blocked: {host} not in whitelist")
            return

        import http.client
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if parsed.scheme == "https":
                import ssl
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=30)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=30)

            # Read body if present
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else None

            # Forward headers (skip proxy-specific ones)
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("proxy-connection", "proxy-authorization", "host")}
            headers["Host"] = host

            path = parsed.path
            if parsed.query:
                path += "?" + parsed.query

            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()

            self.send_response(resp.status)
            for key, val in resp.getheaders():
                if key.lower() not in ("transfer-encoding",):
                    self.send_header(key, val)
            self.end_headers()
            self.wfile.write(resp.read())
            conn.close()
        except Exception as e:
            self.send_error(502, f"Proxy error: {e}")

    def log_message(self, format, *args):
        # Suppress noisy logs
        pass


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    server = ThreadedHTTPServer(("127.0.0.1", LISTEN_PORT), ProxyHandler)
    print(f"[whitelist_proxy] Listening on 127.0.0.1:{LISTEN_PORT}", flush=True)
    print(f"[whitelist_proxy] Allowed domains: {len(ALLOWED_DOMAINS)}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
