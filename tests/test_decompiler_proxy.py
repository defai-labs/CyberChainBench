"""Offline regressions for the decompiler's whitelisted service."""

import contextlib
import http.client
import importlib.util
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
decompiler = importlib.import_module("infra.cli.get_decompiled_contract")

spec = importlib.util.spec_from_file_location(
    "whitelist_proxy", ROOT / "scripts/whitelist_proxy.py"
)
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)

SYNTHETIC_HTML = (
    '<html><a class="anchor" name="func_synthetic"></a>'
    "<pre>function synthetic() { return 1 &lt; 2 &amp;&amp; 3 &gt; 2; }</pre></html>"
)
SYNTHETIC_TEXT = "function synthetic() { return 1 < 2 && 3 > 2; }"


@contextlib.contextmanager
def running_proxy():
    server = proxy.ThreadedHTTPServer(("127.0.0.1", 0), proxy.ProxyHandler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextlib.contextmanager
def proxy_client(address, request):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(address)
        client.sendall(request)
        yield client


def receive_headers(client):
    response = b""
    while not response.endswith(b"\r\n\r\n"):
        data = client.recv(1)
        if not data:
            break
        response += data
    return response


class ProxyAllowlistTests(unittest.TestCase):
    def test_decompiler_service_is_not_in_general_domain_allowlist(self):
        for hostname in ("ethervm.io", "ETHERVM.IO", "www.ethervm.io", "api.tools.ethervm.io"):
            with self.subTest(hostname=hostname):
                self.assertFalse(proxy.is_allowed(hostname))

    def test_rejects_unrelated_and_lookalike_domains(self):
        for hostname in (
            "example.net",
            "evilethervm.io",
            "ethervm.io.evil.example",
            "ethervm-io.example",
            "ethervm.io@evil.example",
            "ethervm.io.",
            "192.0.2.1",
            "169.254.169.254",
        ):
            with self.subTest(hostname=hostname):
                self.assertFalse(proxy.is_allowed(hostname))

    def test_existing_domain_policy_is_preserved(self):
        for hostname in ("api.etherscan.io", "api.openai.com", "127.0.0.1"):
            self.assertTrue(proxy.is_allowed(hostname))
        for domain in proxy.ALLOWED_DOMAINS:
            with self.subTest(domain=domain):
                self.assertTrue(proxy.is_allowed(domain))
                self.assertTrue(proxy.is_allowed("api." + domain))
        self.assertFalse(proxy.is_allowed("evilopenai.com"))

    def test_connect_forwards_bytes_to_stubbed_upstream(self):
        remote, upstream = socket.socketpair()
        with remote, upstream, running_proxy() as address:
            upstream.settimeout(2)
            with mock.patch.object(
                proxy.socket, "create_connection", return_value=remote
            ) as connect:
                request = b"CONNECT ethervm.io:443 HTTP/1.1\r\nHost: ethervm.io:443\r\n\r\n"
                with proxy_client(address, request) as client:
                    self.assertTrue(receive_headers(client).startswith(b"HTTP/1.0 200 "))
                    connect.assert_called_once_with(("ethervm.io", 443), timeout=10)
                    client.sendall(b"synthetic request")
                    self.assertEqual(upstream.recv(1024), b"synthetic request")
                    upstream.sendall(b"synthetic response")
                    self.assertEqual(client.recv(1024), b"synthetic response")
                    client.shutdown(socket.SHUT_WR)
                    self.assertEqual(upstream.recv(1), b"")

    def test_blocked_connect_never_opens_upstream(self):
        authorities = (
            "example.net:443",
            "evilethervm.io:443",
            "ethervm.io.evil.example:443",
            "www.ethervm.io:443",
            "api.tools.ethervm.io:443",
            "ethervm.io",
            "ethervm.io:0",
            "ethervm.io:1",
            "ethervm.io:80",
            "ethervm.io:442",
            "ethervm.io:444",
            "ethervm.io:8443",
            "ethervm.io:65535",
            "ethervm.io:65536",
            "ethervm.io:0443",
            "ethervm.io:",
            "ethervm.io:-1",
            "ethervm.io:+443",
            "ethervm.io:https",
            "ethervm.io:443x",
            "ethervm.io:443:80",
            "ethervm.io.:443",
            "user@ethervm.io:443",
            "user:pass@ethervm.io:443",
            "[ethervm.io]:443",
            "[::1]:443",
            "ethervm.io]:443",
            "https://ethervm.io:443",
            "ethervm.io:443/path",
            "ethervm.io:443?query",
            "ethervm.io:443#fragment",
            "ethervm%2eio:443",
            "ethervm..io:443",
            "ethervm.io:999999999999999999999",
            "api.etherscan.io:0",
            "api.etherscan.io:65536",
            "api.etherscan.io:abc",
            "api.etherscan.io:443:80",
            "user@api.etherscan.io:443",
            "[api.etherscan.io]:443",
            "api.etherscan.io.:443",
            "-api.etherscan.io:443",
            "api-.etherscan.io:443",
            "a" * 64 + ".etherscan.io:443",
            ".".join(["a" * 63] * 4) + ".etherscan.io:443",
        )
        with running_proxy() as address:
            with mock.patch.object(proxy.socket, "create_connection") as connect:
                for authority in authorities:
                    with self.subTest(authority=authority):
                        request = f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode()
                        with proxy_client(address, request) as client:
                            self.assertTrue(receive_headers(client).startswith(b"HTTP/1.0 403 "))
                connect.assert_not_called()

    def test_allowed_connect_destinations_keep_expected_ports_and_default(self):
        authorities = {
            "api.etherscan.io:80": ("api.etherscan.io", 80),
            "API.OPENAI.COM:8443": ("api.openai.com", 8443),
            "localhost": ("localhost", 443),
            "127.0.0.1:18080": ("127.0.0.1", 18080),
            "api.etherscan.io:00080": ("api.etherscan.io", 80),
            "ETHERVM.IO:443": ("ethervm.io", 443),
        }
        with running_proxy() as address:
            for authority, target in authorities.items():
                with self.subTest(authority=authority):
                    remote, upstream = socket.socketpair()
                    with remote, upstream:
                        upstream.settimeout(2)
                        with mock.patch.object(
                            proxy.socket, "create_connection", return_value=remote
                        ) as connect:
                            request = f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode()
                            with proxy_client(address, request) as client:
                                self.assertTrue(
                                    receive_headers(client).startswith(b"HTTP/1.0 200 ")
                                )
                                connect.assert_called_once_with(target, timeout=10)
                            self.assertEqual(upstream.recv(1), b"")

    def test_non_connect_requests_to_decompiler_are_blocked(self):
        with running_proxy() as address:
            with mock.patch.object(http.client, "HTTPConnection") as http_connect:
                with mock.patch.object(http.client, "HTTPSConnection") as https_connect:
                    for url in ("http://ethervm.io/decompile", "https://ethervm.io/decompile"):
                        with self.subTest(url=url):
                            request = f"GET {url} HTTP/1.1\r\n\r\n".encode()
                            with proxy_client(address, request) as client:
                                self.assertTrue(
                                    receive_headers(client).startswith(b"HTTP/1.0 403 ")
                                )
                    http_connect.assert_not_called()
                    https_connect.assert_not_called()


class DecompilerTests(unittest.TestCase):
    def test_pinned_request_uses_allowed_service_and_extracts_response(self):
        with mock.patch.object(
            decompiler.urllib.request, "urlopen", return_value=io.BytesIO(SYNTHETIC_HTML.encode())
        ) as urlopen:
            result = decompiler._decompile_via_ethervm(" 0x6001600055 ", timeout=17)
        self.assertEqual(result, SYNTHETIC_TEXT)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://ethervm.io/decompile")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(
            urllib.parse.parse_qs(request.data.decode()), {"bytecode": ["0x6001600055"]}
        )
        self.assertEqual(request.get_header("User-agent"), "Web3Bug-Benchmark/1.0")
        self.assertEqual(urlopen.call_args.kwargs, {"timeout": 17})

    def test_empty_bytecode_makes_no_request(self):
        with mock.patch.object(decompiler.urllib.request, "urlopen") as urlopen:
            self.assertEqual(decompiler._decompile_via_ethervm(" \n"), "")
            urlopen.assert_not_called()

    def test_cli_writes_synthetic_creation_and_runtime_artifacts(self):
        creation = "0x6001600055"
        runtime = "0x6002600055"
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory) / "output"
            argv = [
                "get_decompiled_contract",
                "--chain",
                "ethereum",
                "--address",
                "0x" + "1" * 40,
                "--output-dir",
                str(output_dir),
                "--timeout",
                "17",
            ]
            stdout = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    decompiler,
                    "lookup_contract_creation",
                    return_value={
                        "ok": True,
                        "creation_bytecode": creation,
                    },
                ) as lookup_creation,
                mock.patch.object(
                    decompiler, "lookup_runtime_code", return_value=runtime
                ) as lookup_runtime,
                mock.patch.object(
                    decompiler.urllib.request,
                    "urlopen",
                    side_effect=lambda *args, **kwargs: io.BytesIO(SYNTHETIC_HTML.encode()),
                ) as urlopen,
                contextlib.redirect_stdout(stdout),
            ):
                decompiler.main()
            result = json.loads(stdout.getvalue())
            self.assertTrue(result["ok"])
            self.assertEqual(result["artifact_mode"], "ethervm")
            self.assertTrue(result["has_creation"])
            self.assertTrue(result["has_runtime"])
            self.assertTrue(result["decompiled"])
            lookup_creation.assert_called_once_with("ethereum", "0x" + "1" * 40)
            lookup_runtime.assert_called_once_with("ethereum", "0x" + "1" * 40)
            self.assertEqual(urlopen.call_count, 2)
            self.assertEqual(
                [
                    urllib.parse.parse_qs(call.args[0].data.decode())["bytecode"][0]
                    for call in urlopen.call_args_list
                ],
                [creation, runtime],
            )
            expected = {
                "creation_bytecode.hex": creation + "\n",
                "runtime_bytecode.hex": runtime + "\n",
                "creation_decompiled.txt": SYNTHETIC_TEXT + "\n",
                "runtime_decompiled.txt": SYNTHETIC_TEXT + "\n",
            }
            for name, content in expected.items():
                self.assertEqual(Path(result["paths"][name]).read_text(), content)
            combined = Path(result["paths"]["decompiled.txt"]).read_text()
            self.assertIn("CONSTRUCTOR (creation code)", combined)
            self.assertIn("CONTRACT LOGIC (runtime code)", combined)
            self.assertEqual(combined.count(SYNTHETIC_TEXT), 2)


if __name__ == "__main__":
    unittest.main()
